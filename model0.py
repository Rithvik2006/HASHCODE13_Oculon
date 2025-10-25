# requirements:
# pip install torch torchvision torchaudio datasets scikit-learn pandas numpy tqdm

import os
import numpy as np
import pandas as pd 
from datasets import load_dataset
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score, precision_recall_fscore_support
import torch 
from torch import nn
from torch.utils.data import Dataset, DataLoader
from tqdm import tqdm

# ---------- 1. Load dataset from Hugging Face ----------
# This will download and cache dataset locally via the datasets library.
ds = load_dataset("onurkya7/NADW-network-attacks-dataset", split="train")  # may use "train", "test" as available
# quick peek
print(ds.features)  # to see column names and types

# Convert to pandas (careful with very large datasets; consider streaming)
df = ds.to_pandas()

# ---------- 2. Quick preprocessing ----------
# Identify the label column (adjust if your dataset uses a different name)
label_col = None
for candidate in ["label", "attack", "Attack", "class", "target"]:
    if candidate in df.columns:
        label_col = candidate
        break
if label_col is None:
    # If there's no explicit label column, you will need to map columns to attack/normal
    # For now we raise informative error
    raise ValueError("No label column found. Please set `label_col` to your dataset's label column name.")

# If labels are text, encode them
if df[label_col].dtype == object:
    le = LabelEncoder()
    df[label_col] = le.fit_transform(df[label_col].astype(str))
    print("Label mapping:", dict(enumerate(le.classes_)))

# Separate features and label
X = df.drop(columns=[label_col])
y = df[label_col].astype(int)

# Keep only numeric columns for baseline; for production include engineered flow features, categorical encoding
numeric_cols = X.select_dtypes(include=[np.number]).columns.tolist()
print("Numeric columns detected:", numeric_cols)

X_num = X[numeric_cols].fillna(0.0)  # simple NA handling

# Scale numeric features
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X_num)

# ---------- 3. Train / val / test split (stratified if labels present) ----------
X_train, X_temp, y_train, y_temp = train_test_split(X_scaled, y, test_size=0.3, stratify=y, random_state=42)
X_val, X_test, y_val, y_test = train_test_split(X_temp, y_temp, test_size=0.5, stratify=y_temp, random_state=42)

# ---------- 4. PyTorch datasets ----------
class TabularDataset(Dataset):
    def __init__(self, X, y=None):
        self.X = torch.tensor(X, dtype=torch.float32)
        self.y = None if y is None else torch.tensor(y.values if isinstance(y, pd.Series) else y, dtype=torch.long)
    def __len__(self):
        return self.X.shape[0]
    def __getitem__(self, idx):
        if self.y is None:
            return self.X[idx]
        return self.X[idx], self.y[idx]

train_ds = TabularDataset(X_train, y_train)
val_ds = TabularDataset(X_val, y_val)
test_ds = TabularDataset(X_test, y_test)

train_loader = DataLoader(train_ds, batch_size=512, shuffle=True, num_workers=2)
val_loader = DataLoader(val_ds, batch_size=512, shuffle=False, num_workers=2)
test_loader = DataLoader(test_ds, batch_size=512, shuffle=False, num_workers=2)


# ---------- 5A. Autoencoder (unsupervised anomaly detection) ----------
class AE(nn.Module):
    def __init__(self, input_dim, latent_dim=32):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 128),
            nn.ReLU(),
            nn.Linear(128, 64),
            nn.ReLU(),
            nn.Linear(64, latent_dim)
        )
        self.decoder = nn.Sequential(
            nn.Linear(latent_dim, 64),
            nn.ReLU(),
            nn.Linear(64, 128),
            nn.ReLU(),
            nn.Linear(128, input_dim)
        )
    def forward(self, x):
        z = self.encoder(x)
        out = self.decoder(z)
        return out

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
ae = AE(input_dim=X_train.shape[1], latent_dim=32).to(device)
ae_opt = torch.optim.Adam(ae.parameters(), lr=1e-3)
ae_loss_fn = nn.MSELoss()

# Train autoencoder on "normal" only if label 0 is normal.
normal_idx = (y_train == 0).values if hasattr(y_train, "values") else (y_train == 0)
if normal_idx.sum() < 32:
    print("Warning: not enough normal samples to train AE on normal-only; training on all data instead.")
    normal_train_data = X_train
else:
    normal_train_data = X_train[normal_idx]

normal_loader = DataLoader(TabularDataset(normal_train_data), batch_size=512, shuffle=True)

# AE training loop (short)
for epoch in range(10):
    ae.train()
    total_loss = 0.0
    for xb in normal_loader:
        xb = xb.to(device)
        ae_opt.zero_grad()
        recon = ae(xb)
        loss = ae_loss_fn(recon, xb)
        loss.backward()
        ae_opt.step()
        total_loss += loss.item() * xb.size(0)
    print(f"AE Epoch {epoch+1}: train loss {total_loss / len(normal_loader.dataset):.6f}")

# Compute reconstruction error on validation set to pick threshold
ae.eval()
errors = []
with torch.no_grad():
    for xb in val_loader:
        x = xb[0].to(device) if isinstance(xb, tuple) else xb.to(device)
        recon = ae(x)
        err = torch.mean((recon - x)**2, dim=1).cpu().numpy()
        errors.extend(err)
errors = np.array(errors)
# e.g., threshold = mean + 3*std
thr = errors.mean() + 3 * errors.std()
print("AE anomaly threshold:", thr)

# ---------- 5B. LSTM classifier (supervised) ----------
# For sequence models you typically create fixed-length windows by session or time.
# Here we treat each row as an independent sample (tabular -> MLP or 1D conv). For LSTM we need sequential windows.
# Example: create windows of size W from the scaled features (simple sliding windows)
def make_windows(Xarr, yarr, W=8, step=1):
    Xw, yw = [], []
    n = Xarr.shape[0]
    for i in range(0, n - W + 1, step):
        Xw.append(Xarr[i:i+W])
        yw.append(yarr[i+W-1])  # label of last item in window (heuristic)
    return np.stack(Xw), np.array(yw)

W = 8
Xw_train, yw_train = make_windows(X_train, y_train.values, W=W)
Xw_val, yw_val = make_windows(X_val, y_val.values, W=W)
Xw_test, yw_test = make_windows(X_test, y_test.values, W=W)

class SeqDataset(Dataset):
    def __init__(self, Xseq, y=None):
        self.X = torch.tensor(Xseq, dtype=torch.float32)  # shape (N, W, F)
        self.y = None if y is None else torch.tensor(y, dtype=torch.long)
    def __len__(self):
        return self.X.shape[0]
    def __getitem__(self, idx):
        if self.y is None:
            return self.X[idx]
        return self.X[idx], self.y[idx]

batch_size = 128
train_seq_loader = DataLoader(SeqDataset(Xw_train, yw_train), batch_size=batch_size, shuffle=True, num_workers=2)
val_seq_loader = DataLoader(SeqDataset(Xw_val, yw_val), batch_size=batch_size, shuffle=False, num_workers=2)
test_seq_loader = DataLoader(SeqDataset(Xw_test, yw_test), batch_size=batch_size, shuffle=False, num_workers=2)

class LSTMClassifier(nn.Module):
    def __init__(self, input_dim, hidden_size=64, n_layers=1, n_classes=2):
        super().__init__()
        self.lstm = nn.LSTM(input_dim, hidden_size, batch_first=True, num_layers=n_layers, bidirectional=False)
        self.fc = nn.Sequential(
            nn.Linear(hidden_size, 64),
            nn.ReLU(),
            nn.Linear(64, n_classes)
        )
    def forward(self, x):
        # x: (B, W, F)
        _, (h_n, _) = self.lstm(x)  # h_n: (num_layers * num_directions, B, hidden_size)
        h = h_n[-1]  # last layer
        return self.fc(h)

n_classes = len(np.unique(y))  # multi-class if present
lstm = LSTMClassifier(input_dim=X_train.shape[1], hidden_size=64, n_layers=1, n_classes=n_classes).to(device)
opt = torch.optim.Adam(lstm.parameters(), lr=1e-3)
criterion = nn.CrossEntropyLoss()

def train_epoch(model, loader, optimizer):
    model.train()
    total_loss = 0.0
    for xb, yb in loader:
        xb, yb = xb.to(device), yb.to(device)
        optimizer.zero_grad()
        logits = model(xb)
        loss = criterion(logits, yb)
        loss.backward()
        optimizer.step()
        total_loss += loss.item() * xb.size(0)
    return total_loss / len(loader.dataset)

def eval_model(model, loader):
    model.eval()
    preds = []
    trues = []
    with torch.no_grad():
        for xb, yb in loader:
            xb = xb.to(device)
            logits = model(xb)
            pred = torch.argmax(logits, dim=1).cpu().numpy()
            preds.extend(pred)
            trues.extend(yb.numpy())
    return np.array(trues), np.array(preds)

# Train LSTM (few epochs)
for epoch in range(6):
    tr_loss = train_epoch(lstm, train_seq_loader, opt)
    tr, pr = eval_model(lstm, val_seq_loader)
    print(f"LSTM Epoch {epoch+1}, train_loss={tr_loss:.4f}")
    print(classification_report(tr, pr, zero_division=0, digits=4))

# ---------- 5C. 1D-CNN classifier (tabular/time-windowed) ----------
class CNN1DClassifier(nn.Module):
    def __init__(self, seq_len, n_features, n_classes):
        super().__init__()
        # treat each feature as a channel? simpler: conv over time across features
        self.conv = nn.Sequential(
            nn.Conv1d(in_channels=n_features, out_channels=64, kernel_size=3, padding=1),
            nn.ReLU(),
            nn.Conv1d(64, 128, kernel_size=3, padding=1),
            nn.ReLU(),
            nn.AdaptiveAvgPool1d(1)
        )
        self.fc = nn.Sequential(
            nn.Flatten(),
            nn.Linear(128, 64),
            nn.ReLU(),
            nn.Linear(64, n_classes)
        )
    def forward(self, x):
        # x shape: (B, W, F) -> transpose to (B, F, W)
        x = x.transpose(1, 2)
        c = self.conv(x)
        return self.fc(c)

cnn = CNN1DClassifier(seq_len=W, n_features=X_train.shape[1], n_classes=n_classes).to(device)
opt_cnn = torch.optim.Adam(cnn.parameters(), lr=1e-3)

# Train CNN quickly
for epoch in range(6):
    cnn.train()
    total_loss = 0.0
    for xb, yb in train_seq_loader:
        xb, yb = xb.to(device), yb.to(device)
        opt_cnn.zero_grad()
        logits = cnn(xb)
        loss = criterion(logits, yb)
        loss.backward()
        opt_cnn.step()
        total_loss += loss.item() * xb.size(0)
    tr, pr = eval_model(cnn, val_seq_loader)
    print(f"CNN Epoch {epoch+1}, loss {total_loss/len(train_seq_loader.dataset):.4f}")
    print(classification_report(tr, pr, zero_division=0, digits=4))

# ---------- 6. Final evaluation on test data ----------
y_true_ae = []
y_pred_ae = []
ae.eval()
with torch.no_grad():
    for xb, yb in test_loader:
        x = xb.to(device)
        recon = ae(x)
        err = torch.mean((recon - x)**2, dim=1).cpu().numpy()
        y_true_ae.extend(yb.numpy())
        y_pred_ae.extend((err > thr).astype(int))  # anomaly=1

print("AE-based anomaly detection report (treated as binary):")
print(classification_report(y_true_ae, y_pred_ae, zero_division=0, digits=4))

# LSTM test
y_true_lstm, y_pred_lstm = eval_model(lstm, test_seq_loader)
print("LSTM test report:")
print(classification_report(y_true_lstm, y_pred_lstm, zero_division=0, digits=4))

# CNN test
y_true_cnn, y_pred_cnn = eval_model(cnn, test_seq_loader)
print("CNN test report:")
print(classification_report(y_true_cnn, y_pred_cnn, zero_division=0, digits=4))

# Save models
os.makedirs("models", exist_ok=True)
torch.save(ae.state_dict(), "models/autoencoder.pth")
torch.save(lstm.state_dict(), "models/lstm_classifier.pth")
torch.save(cnn.state_dict(), "models/cnn1d_classifier.pth")
print("Models saved to ./models/")

def build_flux_query(bucket: str, measurement: str = None, field: str = None, tags: dict = None, minutes: int = 15) -> str:
    measurement = measurement or ""
    field_filter = f'and r._field == "{field}"' if field else ""
    tag_filters = ""
    if tags:
        for k, v in tags.items():
            tag_filters += f' and r["{k}"] == "{v}"'
    flux = (
        f'from(bucket: "{bucket}") |> range(start: -{minutes}m) '
        f'|> filter(fn: (r) => r["_measurement"] == "{measurement}" {field_filter} {tag_filters}) '
        f'|> aggregateWindow(every: 1m, fn: mean, createEmpty: false) |> yield(name: "mean")'
    )
    return flux

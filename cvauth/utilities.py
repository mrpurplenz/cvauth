"""
Utility helpers used across CVAuth modules.
"""

def station2call(station: str) -> str:
    """
    Convert a station identifier into a base callsign.

    Examples
    --------
    ZL2DRS      -> ZL2DRS
    ZL2DRS-4    -> ZL2DRS
    zl2drs-4    -> ZL2DRS
    ZL2DRS*     -> ZL2DRS

    Returns
    -------
    str
        Uppercase base callsign suitable for key lookup.
    """
    if not station:
        return ""

    station = station.upper().strip()

    # remove digi marker
    station = station.rstrip("*")

    # remove SSID
    if "-" in station:
        station = station.split("-", 1)[0]

    return station

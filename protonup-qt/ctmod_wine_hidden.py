# ctmod_wine_hidden.py — ProtonUp-Qt compatibility-tool module for wine-cloak builds.
#
# TEMPLATE: ProtonUp-Qt's ctmod API changes between releases. Before shipping, open the
# ctmod for a tool you already have (e.g. pupgui2/ctmods/ctmod_geproton.py) in YOUR installed
# ProtonUp-Qt and match its method signatures. Drop this file into the ctmods directory:
#   native : <python site-packages>/pupgui2/ctmods/
#   flatpak: ~/.var/app/net.davidotek.pupgui2/data/... (see ProtonUp-Qt docs)
#
# Publish your packaged tarball (./wine-cloak package ... --name GE-Proton-Hidden) as a
# GitHub release whose asset is the .tar.gz, then set CT_URL below to that repo's API.

import os
import requests
from PySide6.QtCore import QObject, QCoreApplication, Signal, Property

CT_NAME = 'Wine-Hidden'
CT_LAUNCHERS = ['steam', 'lutris', 'advmode']   # 'steam' only if the build is a full Proton
CT_DESCRIPTION = {'en': QCoreApplication.instance().translate(
    '', 'Anti-detection Wine/GE-Proton (wine-cloak): presents as a clean bare-metal Windows '
        'box for malware analysis / compatibility. Not for game anti-cheat evasion.'
) if QCoreApplication.instance() else 'Anti-detection Wine/GE-Proton (wine-cloak).'}


class CtInstaller(QObject):

    BUFFER_SIZE = 65536
    CT_URL = 'https://api.github.com/repos/YOUR_GH_USER/wine-cloak-releases/releases'
    CT_INFO_URL = 'https://github.com/YOUR_GH_USER/wine-cloak-releases/releases/tag/'

    p_download_progress_percent = 0
    download_progress_percent = Signal(int)

    def __init__(self, main_window=None):
        super().__init__()
        self.p_download_canceled = False
        self.rs = main_window.rs if main_window and getattr(main_window, 'rs', None) else requests.Session()

    # --- plumbing expected by ProtonUp-Qt ---
    def get_download_canceled(self):
        return self.p_download_canceled

    def set_download_canceled(self, val):
        self.p_download_canceled = val

    download_canceled = Property(bool, get_download_canceled, set_download_canceled)

    def __set_download_progress_percent(self, value: int):
        if self.p_download_progress_percent == value:
            return
        self.p_download_progress_percent = value
        self.download_progress_percent.emit(value)

    def __download(self, url, destination):
        try:
            r = self.rs.get(url, stream=True)
            r.raise_for_status()
        except requests.exceptions.RequestException:
            return False
        total = int(r.headers.get('content-length', 0))
        got = 0
        os.makedirs(os.path.dirname(destination), exist_ok=True)
        with open(destination, 'wb') as f:
            for chunk in r.iter_content(chunk_size=self.BUFFER_SIZE):
                if self.p_download_canceled:
                    return False
                f.write(chunk)
                got += len(chunk)
                if total:
                    self.__set_download_progress_percent(int(got / total * 100))
        return True

    # --- API ProtonUp-Qt calls ---
    def fetch_releases(self, count=100, page=1):
        try:
            tags = self.rs.get(f'{self.CT_URL}?per_page={count}&page={page}').json()
            return [r['tag_name'] for r in tags if not r.get('draft')]
        except Exception:
            return []

    def get_tool(self, version, install_dir, temp_dir):
        """Download the release asset and extract it into install_dir/<name>."""
        try:
            rel = self.rs.get(f'{self.CT_URL}/tags/{version}').json()
            asset = next((a for a in rel.get('assets', []) if a['name'].endswith(('.tar.gz', '.tar.xz'))), None)
            if not asset:
                return False
        except Exception:
            return False

        self.__set_download_progress_percent(1)
        archive = os.path.join(temp_dir, asset['name'])
        if not self.__download(asset['browser_download_url'], archive):
            return False

        import tarfile
        os.makedirs(install_dir, exist_ok=True)
        with tarfile.open(archive) as t:
            t.extractall(install_dir)   # tarball top dir == tool name (from `wine-cloak package`)
        self.__set_download_progress_percent(100)
        return True

    def get_info_url(self, version):
        return self.CT_INFO_URL + version

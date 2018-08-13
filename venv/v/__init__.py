import pkgutil

import_folder = pkgutil.extend_path(__path__, __name__)
pkgutil.extend_path(import_folder, __name__)
for importer, modname, ispkg in pkgutil.walk_packages(path = import_folder, prefix=__name__+'.'):
    __import__(modname)


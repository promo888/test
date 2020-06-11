import os, sys, pkgutil

import_folder = pkgutil.extend_path(__path__, __name__)

pkgutil.extend_path(import_folder, __name__)
#non object versions
# for importer, modname, ispkg in pkgutil.walk_packages(path = import_folder, prefix=__name__+'.'):
#     __import__(modname)
#     print('%s being imported to the workspace' % modname)


#object class versions
# for module in os.listdir(os.path.dirname(__file__)): #modules = os.listdir(os.path.dirname('./v/'))
#     if module == '__init__.py' or module[-3:] != 'py':
#         continue
#     modname = module[:-3]
#     print('%s module being imported to the workspace' % modname)
#     __import__(modname, locals(), globals())


from os.path import dirname, basename, isfile
import glob
modules = os.listdir(os.path.dirname(__file__))
print('Found %s ' % modules)
__all__ = [basename(f)[:-3] for f in modules if not dirname(f) and not '__' in f]
print('Import %s ' % (__all__))
# for module in __all__:
#     __import__(module, locals(), globals())
#sys.path.append(import_folder)

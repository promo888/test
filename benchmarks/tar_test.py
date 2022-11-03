import sys, os, tarfile, glob, shutil, time

if len(sys.argv) < 3 or 'tar' in sys.argv[1] is None or 'tar' in sys.argv[2] is None:
    print("Exiting... Please define params (Paths to tar files). Example: python tardiff.py path1/*.tar path2/*.tar.gz")
    sys.exit(1)

usr = os.environ.get('USERNAME')
home = '/export/home/%s/' % usr
os.system('mkdir -p %s/tardiff' % usr)
os.system('rm -rf %s/tardiff/*' % usr)
tar1path = '%stardiff/tar1/' % home
tar2path = '%stardiff/tar2/' % home
diffpath = '%stardiff/diff/' % home
os.system('mkdir -p %s' % tar1path)
os.system('mkdir -p %s' % tar2path)
os.system('mkdir -p %s' % diffpath)
tar1 = sys.argv[1]
tar2 = sys.argv[2]
# test1 = '%sbuild_server/Releases/EBS-UI/production-release1/ebs_admin_all/target/ebs_admin/ebs_admin_full_1.2.409.tar.gz' % home
# test2 = '%sbuild_server/Releases/EBS-UI/production-release1/ebs_admin_all/target/ebs_admin/ebs_admin_full_1.2.410.tar.gz' % home
test1 = '%sbuild_server/Releases/yuniti_ui/8.15.0.0/yuniti_ui_8.15.0.0.tar.gz' % home
test2 = '%sbuild_server/Releases/yuniti_ui/8.15.1.0/yuniti_ui_8.15.1.0.tar.gz' % home

def untar_recursive(path,extract_to):
    excluded = ['mongo', 'redis', 'node', 'packages', 'fixtures']
    with tarfile.open(path, 'r') as tf:
        
        import os
        
        def is_within_directory(directory, target):
            
            abs_directory = os.path.abspath(directory)
            abs_target = os.path.abspath(target)
        
            prefix = os.path.commonprefix([abs_directory, abs_target])
            
            return prefix == abs_directory
        
        def safe_extract(tar, path=".", members=None, *, numeric_owner=False):
        
            for member in tar.getmembers():
                member_path = os.path.join(path, member.name)
                if not is_within_directory(path, member_path):
                    raise Exception("Attempted Path Traversal in Tar File")
        
            tar.extractall(path, members, numeric_owner=numeric_owner) 
            
        
        safe_extract(tf, extract_to)
        tars = glob.glob('%s*tar*' % extract_to)
        for t in tars: os.remove(t)
        # for ex in excluded:
        #     dirs = glob.glob('{}/*{}*'.format(extract_to, ex)
        #     for d in dirs: #TODO to continue of folder
        #         #if os.path.isdir(d): os.remove(d)
        for path, subdirs, files in os.walk(extract_to):
            for name in files:
                a_file = os.path.join(path, name)
                #print(a_file)
                ignored = [s for s in excluded if s in a_file]
                if len(ignored) > 0:
                    #print('%s ignored' % a_file)
                    continue
                if tarfile.is_tarfile(a_file):
                    with tarfile.open(a_file, 'r') as tf2:
                        try:
                            tf2.extractall(extract_to)
                            tars = glob.glob('%s*tar*' % extract_to)
                            for t in tars: os.remove(t)
                        except:
                            pass

            for name in subdirs:
                folder = os.path.join(path, name)
                #print(folder)
                #os.system('rm -rf %s/*tar* *gz 2>/dev/null' % folder)

#TODO to continue
# for ex in excluded:
#     dirs = glob.glob('{}/*{}*'.format(extract_to, ex)
#                      for d in dirs:  # TODO to continue of folder
#     if os.path.isdir(d): os.remove(d)



try:
    untar_recursive(test1, tar1path)
    #untar_recursive(test2, tar2path)

    #os.system('diff --brief --recursive --no-dereference --new-file --no-ignore-file-name-case {} {} > {}/new_files.txt'.format(tar1path, tar2path, diffpath))
    #os.system('diff --brief --recursive {} {} > {}/diff.txt'.format(tar1path, tar2path, diffpath))
except Exception as exc:
    print('Error: %s' % exc)
    print('Error on line {}'.format(sys.exc_info()[-1].tb_lineno))
    print('Exiting...')
    sys.exit(1)

print('See Diff results in ~/tardiff/diff folder')
sys.exit(0)
import os, sys


def spawn(prog, *args):  # имя программы, аргументы командной строки
    stdinFd = sys.stdin.fileno()  # получить дескрипторы потоков
    stdoutFd = sys.stdout.fileno()  # обычно stdin=0, stdout=1
    parentStdin, childStdout = os.pipe()  # создать два канала IPC
    childStdin, parentStdout = os.pipe()  # pipe возвращает (inputfd, outoutfd)
    pid = os.fork()  # создать копию процесса
    if pid:
        os.close(childStdout)  # в родительском после ветвления:
        os.close(childStdin)  # закрыть дочерние концы в родителе
        os.dup2(parentStdin, stdinFd)  # копия sys.stdin = pipe1[0]
        os.dup2(parentStdout, stdoutFd)  # копия sys.stdout = pipe2[1]
    else:
        os.close(parentStdin)  # в дочернем после ветвления:
        os.close(parentStdout)  # закрыть родительские концы
        os.dup2(childStdin, stdinFd)  # копия sys.stdin = pipe2[0]
        os.dup2(childStdout, stdoutFd)  # копия sys.stdout = pipe1[1]
        args = (prog,) + args
        os.execvp(prog, args)  # запустить новую программу
        assert False, 'execvp failed!'  # os.exec никогда не вернется сюда
if __name__ == '__main__':
    mypid = os.getpid()
    spawn('python', 'pipes-testchild.py', 'spam')  # породить дочернюю прогр.
    print('Hello 1 from parent', mypid)  # в stdin дочерней прогр.
    sys.stdout.flush()  # вытолкнуть буфер stdio
    reply = input()  # из потока вывода потомка
    sys.stderr.write('Parent got: "%s"\n' % reply)  # stderr не связан # с каналом!
    
    print('Hello 2 from parent', mypid)
    sys.stdout.flush()
    reply = sys.stdin.readline()
    sys.stderr.write('Parent got: "%s"\n' % reply[:-1])

#https://www.blog.pythonlibrary.org/2016/08/02/python-201-a-multiprocessing-tutorial/

# import multiprocessing as mp
# import time
#
# fn = 'c:/temp/temp.txt'
#
#
# def worker(arg, q):
#     '''stupidly simulates long running process'''
#     start = time.clock()
#     s = 'this is a test'
#     txt = s
#     for i in range(200000):
#         txt += s
#     done = time.clock() - start
#     with open(fn, 'rb') as f:
#         size = len(f.read())
#     res = 'Process' + str(arg), str(size), done
#     q.put(res)
#     return res
#
#
# def listener(q):
#     '''listens for messages on the q, writes to file. '''
#
#     f = open(fn, 'wb')
#     while 1:
#         m = q.get()
#         if m == 'kill':
#             f.write('killed')
#             print(str(m) + ' killed')
#             break
#         print(str(m))
#         f.write(str(m) + '\n')
#         f.flush()
#     f.close()
#
#
# def main():
#     start = time.time()
#     # must use Manager queue here, or will not work
#     manager = mp.Manager()
#     q = manager.Queue()
#     #print('mp.cpu_count %s' % mp.cpu_count())
#     pool = mp.Pool(mp.cpu_count()) # + 2)
#
#     # put listener to work first
#     watcher = pool.apply_async(listener, (q,))
#
#     # fire off workers
#     jobs = []
#     for i in range(10):
#         job = pool.apply_async(worker, (i, q))
#         #print(job)
#         jobs.append(job)
#
#     # collect results from the workers through the pool result queue
#     for job in jobs:
#         item = job.get()
#         print(item)
#
#         f = open(fn, 'a')
#         f.write(str(item) + '\n')
#         f.flush()
#         f.close()
#
#     # now we are done, kill the listener
#     q.put('kill')
#     pool.close()
#     print("Took %s secs for %s procs" % (time.time()-start, mp.cpu_count()) )
#
#
# if __name__ == "__main__":
#     main()

# import multiprocessing
#
# def Writer(dest_filename, some_queue, some_stop_token):
#     with open(dest_filename, 'a') as dest_file:
#         while True:
#             line = some_queue.get()
#             if line == some_stop_token:
#                 return
#             dest_file.write(line)
#
#
# def the_job(some_queue):
#     for item in something:
#         result = process(item)
#         print(item)
#         some_queue.put(result)
#
#
# if __name__ == "__main__":
#     queue = multiprocessing.Queue()
#
#     STOP_TOKEN = "STOP!!!"
#
#     writer_process = multiprocessing.Process(target=Writer, args=("output.txt", queue, STOP_TOKEN))
#     writer_process.start()
#
#     # Dispatch all the jobs
#
#     # Make sure the jobs are finished
#
#     queue.put(STOP_TOKEN)
#     writer_process.join()
#     # There, your file was written.

# import os, time
#
# from multiprocessing import Process
#
#
# def doubler(number):
#     """
#     A doubling function that can be used by a process
#     """
#     result = number * 2
#     proc = os.getpid()
#     print('{0} doubled to {1} by process id: {2}'.format(number, result, proc))
#     with open('output.txt', 'a') as f:
#         f.write(str(result) + '\n')
#
# def p(v):
#     print(v)
#
# def pp(v):
#     print('None')
#
# def vfunc(func, value):
#     func(value)
#
#
# if __name__ == '__main__':
#     start = time.time()
#     numbers = [5, 10, 15, 20, 25, 1, 1, 1, 1 , 1]
#     procs = []
#
#     for index, number in enumerate(numbers):
#         ##proc = Process(target=doubler, args=(number,))
#         proc = Process(target=vfunc, args=(pp, number,))
#         procs.append(proc)
#         proc.start()
#
#     for proc in procs:
#         proc.join(timeout=0.5)
#
#     print("Took %s secs for %s procs" % (time.time() - start, len(numbers)))
#


# import logging
# import multiprocessing
#
# from multiprocessing import Process, Lock
#
#
# def printer(item, lock):
#     """
#     Prints out the item that was passed in
#     """
#     lock.acquire()
#     try:
#         print(item)
#     finally:
#         lock.release()
#
#
# if __name__ == '__main__':
#     lock = Lock()
#     items = ['tango', 'foxtrot', 10]
#     multiprocessing.log_to_stderr()
#     logger = multiprocessing.get_logger()
#     logger.setLevel(logging.INFO)
#     for item in items:
#         p = Process(target=printer, args=(item, lock))
#         p.start()


from multiprocessing import Process, Queue
import os

sentinel = -1


def creator(data, q):
    """
    Creates data to be consumed and waits for the consumer
    to finish processing
    """
    print('{} Creating data and putting it on the queue by {}'.format(q, os.getpid()))
    for item in data:
        q.put(item)


def my_consumer(q):
    """
    Consumes some data and works on it

    In this case, all it does is double the input
    """
    while True:
        data = q.get()
        print('{} data found to be processed: {} by {}'.format(q, data, os.getpid()))
        processed = data * 2
        print(processed)

        if data is sentinel:
            break


if __name__ == '__main__':
    q = Queue()
    data = [5, 10, 13, -1]
    process_one = Process(target=creator, args=(data, q))
    process_two = Process(target=my_consumer, args=(q,))
    process_one.start()
    process_two.start()

    q.close()
    q.join_thread()

    process_one.join()
    process_two.join()
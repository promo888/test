import pika,time


def benchmarkRabbitPersistence(pub=False,sub=False):
    connection = pika.BlockingConnection(pika.ConnectionParameters('89.139.108.95')) #localhost
    channel = connection.channel()


    print("Benchmark Rabbit with persistence...")
    QUEUE = 'test_persistence6'
    duration = 10
    start = time.time()
    buffersize = 10000
    count = 0

    if (pub):
        while(time.time()-start <= duration):
            channel.queue_declare(queue=QUEUE)
            channel.basic_publish(exchange='',
                                  routing_key=QUEUE,
                                  body= 'x' * buffersize,
                                  properties=pika.BasicProperties(
                                      #delivery_mode=2,  # make message persistent
                                  ))

            count += 1

        print(channel.queue_declare(queue=QUEUE))
        print(duration, "sec,", count, " req/res of ", buffersize, " bytes, total: ", count*buffersize/1024/1024/duration, "mb/sec")

    #count2 = 0
    def callback(ch, method, properties, body):
        print(" [x] Received %r" % body)
        #count2 += 1
        pass

    if (sub):
        start = time.time()
        ACK = True #False
        channel.basic_consume(callback,
                              queue=QUEUE,
                              no_ack=ACK,)
        channel.start_consuming()
        #channel.consume(QUEUE, inactivity_timeout=20)
        #time.sleep(2)
        #channel.stop_consuming()
        print(count, "consumed ACK=", ACK, " messages consumed within", (time.time()-start), "secs")


    connection.close()

benchmarkRabbitPersistence(True,True)
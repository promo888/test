# Example 3: asynchronous requests with larger thread pool
import asyncio
import concurrent.futures
import requests
import time

start = time.time()
num = 20
async def main():

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor: #() as executor: #(max_workers=20) as executor: #default 5 threads

        loop = asyncio.get_event_loop()
        futures = [
            loop.run_in_executor(
                executor,
                requests.get,
                'http://www.google.com/'
            )
            for i in range(num)
        ]
        for response in await asyncio.gather(*futures):
            pass


loop = asyncio.get_event_loop()
loop.run_until_complete(main())
print('%s get requests Finished in %ssecs' % (num, time.time() - start))
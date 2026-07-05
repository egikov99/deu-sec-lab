import os
import time
from redis import Redis
from rq import Worker, Queue, Connection

redis_url = os.getenv("REDIS_URL", "redis://redis:6379/0")
listen = ["default"]

if __name__ == "__main__":
    redis = Redis.from_url(redis_url)
    with Connection(redis):
        worker = Worker(list(map(Queue, listen)))
        worker.work(with_scheduler=True)

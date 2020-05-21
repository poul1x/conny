import os
import json
import queue
import logging
import threading
import solver
import traceback

GET_TIMEOUT = 5
INPUT_QUEUE_PATH = 'data/input_queue.json'
OUTPUT_QUEUE_PATH = 'data/output_queue.json'

thread_stop = False
load_queue = queue.Queue()
input_queue = queue.Queue()
output_queue = queue.Queue()
logger = logging.getLogger('solver')


class LoadTask:

    def __init__(self, load_addr, libc_addr, target_addr, ctx):
        self.load_addr = load_addr
        self.libc_addr = libc_addr
        self.target_addr = target_addr
        self.ctx = ctx


class SolverTask:

    def __init__(self, buf, buf_addr, taint, cmp_addr):

        self.buf_addr = buf_addr
        self.cmp_addr = cmp_addr
        self.taint = taint
        self.buf = buf

    @staticmethod
    def deserialize(data):
        return SolverTask(data['buf'], data['buf_addr'],
                          data['taint'], data['cmp_addr'])

    def serialize(self):
        return {
            'buf': self.buf,
            'buf_addr': self.buf_addr,
            'taint': self.taint,
            'cmp_addr': self.cmp_addr,
        }


class SolverResult:

    def __init__(self, buf):
        self.buf = buf

    @staticmethod
    def deserialize(data):
        return SolverResult(data['buf'])

    def serialize(self):
        return {
            'buf': self.buf,
        }


def queue_get(q, nowait=False):
    try:
        if nowait:
            item = q.get_nowait()
        else:
            item = q.get(timeout=GET_TIMEOUT)
    except queue.Empty:
        return None
    else:
        return item


def queue_get_all_items(q):

    data = []
    while True:
        item = queue_get(q, nowait=True)
        if not item:
            break
        else:
            data.append(item.serialize())

    return data


def queue_dump(q, filepath):
    items = queue_get_all_items(q)
    with open(filepath, 'w') as f:
        json.dump(items, f)


def queue_load(q, filepath, class_):

    if not os.path.exists(filepath):
        return

    with open(filepath, 'r') as f:
        json_data = json.load(f)
    queue_put_all_items(q, json_data, class_)


def queue_put_all_items(q, items_list, class_):
    for item in items_list:
        q.put_nowait(class_.deserialize(item))


def queue_merge_blob(q1, q2):

    while True:
        item = queue_get(q2, nowait=True)
        if not item:
            break
        else:
            q1.put_nowait(SolverResult(item.buf))


def load_file(task):
    global load_queue
    assert isinstance(task, LoadTask)
    load_queue.put(task)


def put_task(task):
    global input_queue
    assert isinstance(task, SolverTask)
    input_queue.put(task)


def get_result():
    global output_queue
    item = queue_get(output_queue)
    assert isinstance(item, SolverResult)
    return item


def do_processing():

    global thread_stop, input_queue, output_queue, load_queue

    if thread_stop:
        raise KeyboardInterrupt()

    if not solver.is_initialized():
        item = queue_get(load_queue)
        if item:
            solver.load_binary(item.load_addr, item.libc_addr,
                               item.target_addr, item.ctx)
        return

    item = queue_get(input_queue)
    if thread_stop:
        input_queue.put_nowait(item)
        raise KeyboardInterrupt()

    if not item:
        return

    res, buf1, buf2 = solver.solve_path_constraints(
        item.buf, item.buf_addr, item.taint, item.cmp_addr)

    if res:
        output_queue.put(SolverResult(buf1))
        output_queue.put(SolverResult(buf2))
        msg = f'Constraint solved: cmp_addr={item.cmp_addr} taint={item.taint}'
        logger.info(msg)
    else:
        msg = f'Constraint not solved: cmp_addr={item.cmp_addr} taint={item.taint}'
        logger.error(msg)


def worker():

    while True:
        try:
            do_processing()
        except KeyboardInterrupt:
            break
        except:
            logger.exception(traceback.format_exc())

    logger.info('Solving is interrupted. Thread is stopped')


def start_thread():

    global input_queue, output_queue

    # Load processed inems and those were not
    # Then move not processed items back to test cases queue
    queue_load(output_queue, OUTPUT_QUEUE_PATH, SolverResult)
    queue_load(input_queue, INPUT_QUEUE_PATH, SolverTask)
    queue_merge_blob(output_queue, input_queue)

    th = threading.Thread(name='solver', target=worker)
    th.start()
    return th


def stop_thread(th):

    global thread_stop
    thread_stop = True
    th.join()

    queue_dump(output_queue, OUTPUT_QUEUE_PATH)
    queue_dump(input_queue, INPUT_QUEUE_PATH)

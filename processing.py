import os
import queue
import logging
import threading
import solver
import traceback

GET_TIMEOUT = 5
DATA_DIR = 'data'
OUTPUT_QUEUE_PATH = DATA_DIR + '/output_queue.bin'
TESTCASES = DATA_DIR + '/testcases.bin'

thread_stop = False
load_queue = queue.Queue()
input_queue = queue.Queue()
output_queue = queue.Queue()
logger = logging.getLogger('solver')


class LoadTask:

    def __init__(self, load_addr, libc_addr, target_addr, ctx, length):
        self.load_addr = load_addr
        self.libc_addr = libc_addr
        self.target_addr = target_addr
        self.length = length
        self.ctx = ctx


class SolverTask:

    def __init__(self, buf, buf_addr, taint, taint_offs, cmp_addr):

        self.buf_addr = buf_addr
        self.cmp_addr = cmp_addr
        self.taint_offs = taint_offs
        self.taint = taint
        self.buf = buf


class SolverResult:

    def __init__(self, buf):
        self.buf = buf


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


def queue_merge_blob(q1, q2):

    while True:
        item = queue_get(q2, nowait=True)
        if not item:
            break
        else:
            q1.put_nowait(SolverResult(item.buf))


def put_task(task):
    global input_queue, load_queue

    if isinstance(task, SolverTask):
        input_queue.put(task)
    elif isinstance(task, LoadTask):
        load_queue.put(task)
    else:
        assert False, "Unexpected task type"


def get_result():

    global output_queue
    if output_queue.empty():
        return None

    item = output_queue.get()
    assert isinstance(item, SolverResult)
    return item.buf


def fix_input_data_length(length):

    global output_queue

    if output_queue.empty():
        tc = SolverResult(b'A' * length)
        output_queue.put_nowait(tc)
        return

    while True:
        item = output_queue.get_nowait()
        item_len = len(item.buf)

        if length == item_len:
            break
        elif length < item_len:
            item.buf = item.buf[:length]
        else:
            item.buf = item.buf + b'A' * (length - item_len)

        output_queue.put_nowait(item)


def initialize_solver():

    global load_queue

    item = queue_get(load_queue)
    if not item:
        return False

    fix_input_data_length(item.length)
    solver.load_binary(item.load_addr, item.libc_addr,
                       item.target_addr, item.ctx, item.length)

    logger.info('Binary loaded at 0x%08x, target=0x%08x' %
                (item.load_addr, item.target_addr))
    return True


def do_processing():

    global thread_stop, input_queue, output_queue, load_queue

    if thread_stop:
        raise KeyboardInterrupt()

    if not solver.is_initialized():
        res = initialize_solver()
        if not res:
            return

    item = queue_get(input_queue)
    if thread_stop:
        input_queue.put_nowait(item)
        raise KeyboardInterrupt()

    if not item:
        return

    taint = item.taint
    taint_offs = item.taint_offs
    cmp_addr = item.cmp_addr

    res, buf1, buf2 = solver.solve_path_constraints(
        item.buf.encode(), item.buf_addr, taint, taint_offs, cmp_addr)

    if res:
        output_queue.put(SolverResult(buf1))
        output_queue.put(SolverResult(buf2))
        msg = f'Constraint solved: cmp_addr={hex(cmp_addr)} taint=0x{item.taint}'
        logger.info(msg)

        with open(TESTCASES, "ab") as f:
            f.write(buf1 + b'\n')
            f.write(buf2 + b'\n')

    else:
        msg = f'Constraint not solved: cmp_addr={hex(cmp_addr)} taint=0x{item.taint}'
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

    if not os.path.exists(DATA_DIR):
        os.mkdir(DATA_DIR)

    open(TESTCASES, "wb").close()
    open(OUTPUT_QUEUE_PATH, "wb").close()

    # Start thread
    th = threading.Thread(name='solver', target=worker)
    th.start()
    return th


def stop_thread(th):

    global thread_stop
    thread_stop = True
    th.join()

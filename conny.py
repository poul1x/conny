from aiohttp import web
import asyncio
import logging
import processing


async def index(request):
    return web.Response(text='Conny is running')


async def load_binary(request):

    post_data = await request.post()

    try:

        tc_length = int(post_data['tc_length'], 16)
        load_addr = int(post_data['load_addr'], 16)
        libc_addr = int(post_data['libc_addr'], 16)
        target_addr = int(post_data['target_addr'], 16)
        ctx = {k[4:]: v for k, v in post_data.items()
               if k.startswith('ctx.')}

        ctx['sp'] = int(ctx['sp'], 16)
        ctx['lr'] = int(ctx['lr'], 16)
        ctx['flags'] = int(ctx['flags'], 16)

        for i in range(13):
            j = 'r' + str(i)
            ctx[j] = int(ctx[j], 16)

        task = processing.LoadTask(load_addr, libc_addr, target_addr, ctx, tc_length)
        processing.load_file(task)

    except KeyError as e:
        return web.Response(text='Required parameter is not set: %s' % str(e), status=400)

    return web.Response(text='Binary is loading', status=202)


async def solve_path_constraints(request):

    post_data = await request.post()

    try:
        buf = post_data['buf']
        taint = post_data['taint']
        buf_addr = int(post_data['buf_addr'], 16)
        taint_offs = int(post_data['taint_offs'], 16)
        cmp_addr = int(post_data['cmp_addr'], 16)

        task = processing.SolverTask(buf, buf_addr, taint, taint_offs, cmp_addr)
        processing.put_task(task)

    except KeyError as e:
        return web.Response(text='Required parameter is not set: %s' % str(e), status=400)

    return web.Response(text='Solving...', status=202)


async def prepare_next_testcase(request):

    testcase = processing.get_result()

    if testcase:
        return web.Response(body=testcase, status=200)
    else:
        return web.Response(text='Not ready', status=204)


if __name__ == "__main__":

    fmt = '%(asctime)s %(levelname)-8s %(name)-15s %(message)s'
    logging.basicConfig(level=logging.INFO, format=fmt)

    logger = logging.getLogger('server')
    logger.info('Begin initialization')

    override_args = {
        'logger': logger,
        'access_log': logger,
        'access_log_format': "%a  %s - %r  %b bytes",
    }

    app = web.Application(handler_args=override_args)
    app.router.add_route('GET', '/next', prepare_next_testcase)
    app.router.add_route('POST', '/load', load_binary)
    app.router.add_route('POST', '/solver', solve_path_constraints)

    logger.info('Starting solver thread')
    th = processing.start_thread()

    logger.info('Launching server')
    web.run_app(app)
    print()

    logger.info('Exitting...')
    processing.stop_thread(th)

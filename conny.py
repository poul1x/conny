from aiohttp import web
import asyncio
import logging
import processing

async def index(request):
    return web.Response('Conny is running', status=200)


async def load_binary(request):
    pass

async def solve_path_constraints(request):
    pass

async def prepare_next_testcase(request):

    post_data = await request.post()

    idx = post_data['id']
    rev = post_data['rev']
    mode = post_data['mode']
    mem_usage = post_data['mem_usage']
    cpu_usage = post_data['cpu_usage']



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
    app.router.add_route('POST', '/solve', solve_path_constraints)

    logger.info('Starting solver thread')
    th = processing.start_thread()

    logger.info('Launching server')
    web.run_app(app)
    print()

    logger.info('Exitting...')
    processing.stop_thread(th)


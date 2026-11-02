import asyncio
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from app.request_limits import ExperimentalBodyLimit

def make_app():
    app = FastAPI()
    app.add_middleware(ExperimentalBodyLimit, max_bytes=10)
    @app.post('/api/v1/secure/test')
    async def secured(request: Request):
        return {'size': len(await request.body())}
    @app.post('/api/v1/overview')
    async def demo(request: Request):
        return {'size': len(await request.body())}
    return app

def test_declared_limit_and_demo_is_unaffected():
    client = TestClient(make_app())
    assert client.post('/api/v1/secure/test', content=b'x'*10).json() == {'size':10}
    response = client.post('/api/v1/secure/test', content=b'x'*11)
    assert response.status_code == 413 and response.headers['cache-control'] == 'no-store'
    assert client.post('/api/v1/overview', content=b'x'*20).json() == {'size':20}

def test_oversized_stream_rejected_without_content_length():
    async def scenario():
        messages = iter([{'type':'http.request','body':b'x'*6,'more_body':True},
                         {'type':'http.request','body':b'y'*6,'more_body':False}])
        sent = []
        async def receive(): return next(messages)
        async def send(message): sent.append(message)
        await make_app()({'type':'http','asgi':{'version':'3.0'}, 'http_version':'1.1',
            'method':'POST','scheme':'https','path':'/api/v1/secure/test','raw_path':b'/api/v1/secure/test',
            'query_string':b'', 'headers':[], 'server':('test',443),'client':('127.0.0.1',1),'root_path':''}, receive, send)
        assert sent[0]['status'] == 413
    asyncio.run(scenario())

def test_invalid_or_duplicate_content_length_rejected():
    async def scenario(headers):
        sent=[]
        async def receive(): return {'type':'http.request','body':b'','more_body':False}
        async def send(message): sent.append(message)
        await make_app()({'type':'http','asgi':{'version':'3.0'}, 'http_version':'1.1', 'method':'POST',
            'scheme':'https', 'path':'/api/v1/secure/test','raw_path':b'/api/v1/secure/test', 'query_string':b'',
            'headers':headers,'server':('test',443),'client':('127.0.0.1',1),'root_path':''}, receive, send)
        assert sent[0]['status'] == 400
        assert (b'cache-control', b'no-store') in sent[0]['headers']
        assert (b'x-content-type-options', b'nosniff') in sent[0]['headers']
    asyncio.run(scenario([(b'content-length', b'-1')]))
    asyncio.run(scenario([(b'content-length', b'1'),(b'content-length', b'2')]))
    asyncio.run(scenario([(b'Content-Length', b'1'),(b'Transfer-Encoding', b'chunked')]))

def test_main_application_has_guard_enabled_even_when_routes_disabled():
    from app.main import app
    client = TestClient(app)
    response = client.post('/api/v1/secure/login', content=b'x'*16385)
    assert response.status_code == 413

def test_all_secure_responses_are_not_cacheable_including_errors():
    from fastapi.responses import JSONResponse
    app = FastAPI()
    app.add_middleware(ExperimentalBodyLimit)
    @app.get('/api/v1/secure/cached')
    def cached():
        return JSONResponse({'value':'sensitive'}, headers={'Cache-Control':'public, max-age=600'})
    @app.get('/api/v1/secure/crash')
    def crash():
        raise RuntimeError('secret must not be returned')
    client = TestClient(app, raise_server_exceptions=False)
    for response in [client.get('/api/v1/secure/cached'), client.get('/api/v1/secure/missing'),
                     client.post('/api/v1/secure/cached'), client.get('/api/v1/secure/crash')]:
        assert response.headers['cache-control'] == 'no-store'
        assert response.headers['x-content-type-options'] == 'nosniff'
        assert 'secret must not be returned' not in response.text
    assert client.get('/api/v1/secure/crash').status_code == 500
    assert 'cache-control' not in client.get('/not-secure').headers

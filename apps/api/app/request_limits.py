"""ASGI body size guard for the experimental API.

This guard checks both declared and streamed body sizes. It is defense in depth,
not a replacement for limits/timeouts at a trusted reverse proxy. Only routes
under the experimental prefix are affected; the demo endpoint is unchanged.
"""
import json

class _BodyTooLarge(Exception):
    pass

class ExperimentalBodyLimit:
    def __init__(self, app, max_bytes: int = 16384):
        if max_bytes <= 0:
            raise ValueError('max_bytes must be positive')
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http' or not (scope.get('path', '') == '/api/v1/secure' or scope.get('path', '').startswith('/api/v1/secure/')):
            await self.app(scope, receive, send)
            return

        async def reject(status, detail):
            body = json.dumps({'detail': detail}).encode()
            await send({'type': 'http.response.start', 'status': status, 'headers': [
                (b'content-type', b'application/json'), (b'cache-control', b'no-store'),
                (b'x-content-type-options', b'nosniff'),
                (b'content-length', str(len(body)).encode())]})
            await send({'type': 'http.response.body', 'body': body})

        lengths = [value for key, value in scope.get('headers', []) if key.lower() == b'content-length']
        # Reject ambiguous framing if a proxy/server forwards both headers.
        # This cannot repair disagreement that occurred before the ASGI layer.
        transfer_encodings = [value for key, value in scope.get('headers', []) if key.lower() == b'transfer-encoding']
        if lengths and transfer_encodings:
            await reject(400, 'Invalid request framing')
            return
        if len(lengths) > 1 or (lengths and (not lengths[0].isdigit() or len(lengths[0]) > 12)):
            await reject(400, 'Invalid content length')
            return
        if lengths and int(lengths[0]) > self.max_bytes:
            await reject(413, 'Request body too large')
            return

        total = 0
        started = False
        async def limited_receive():
            nonlocal total
            message = await receive()
            if message['type'] == 'http.request':
                total += len(message.get('body', b''))
                if total > self.max_bytes:
                    raise _BodyTooLarge()
            return message

        async def guarded_send(message):
            nonlocal started
            if message['type'] == 'http.response.start':
                started = True
                headers = [(k, v) for k, v in message.get('headers', [])
                           if k.lower() not in (b'cache-control', b'x-content-type-options')]
                message = {**message, 'headers': headers + [
                    (b'cache-control', b'no-store'), (b'x-content-type-options', b'nosniff')]}
            await send(message)
        try:
            await self.app(scope, limited_receive, guarded_send)
        except _BodyTooLarge:
            # Experimental routes consume their body before emitting a response.
            # If a future streaming route responds first, abort rather than emit
            # a second response or allow it to process an oversized request.
            if started:
                raise
            await reject(413, 'Request body too large')
        except Exception:
            # Send a generic non-cacheable error before re-raising for server logging.
            # Once a response has begun, the server must abort rather than send twice.
            if not started:
                await reject(500, 'Internal server error')
            raise

"""Aggiunge al logger JSON OpenCanary le risposte HTTP di errore."""
from pathlib import Path
from opencanary.modules.http import Error

_original_render = Error.render


def _render_with_log(self, request):
    factory = self.factory
    factory.log(
        {
            'PATH': request.path,
            'QUERY_STRING': request.uri.partition(b'?')[2],
            'USERAGENT': request.getHeader('user-agent') or '<not supplied>',
            'REQUEST_TYPE': request.method,
            'STATUS': int(self.error_code),
        },
        transport=request.transport,
        logtype=(factory.logger.LOG_HTTP_GET if request.method == b'GET'
                 else factory.logger.LOG_HTTP_UNIMPLEMENTED_METHOD),
    )
    return _original_render(self, request)


Error.render = _render_with_log
_original_tac = Path('/usr/local/bin/opencanary.tac')
exec(compile(_original_tac.read_bytes(), str(_original_tac), 'exec'))

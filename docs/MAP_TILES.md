# Cartografia dashboard

La dashboard operativa riutilizza Leaflet 1.9.4 e carica direttamente
`https://tile.openstreetmap.org/{z}/{x}/{y}.png`, senza API key.
Il precedente endpoint CARTO restituiva immagini HTTP 200 con il messaggio
“API KEY REQUIRED”; non era un errore del servizio GeoIP.

Per un deployment enterprise configurare il meta tag `hpx-tile-url` in
`frontend/dashboard_live.html` con il template HTTPS del proprio tile server
OSM, per esempio `https://maps.example.org/{z}/{x}/{y}.png`.
Il file statico può essere fornito anche tramite bind mount nel deployment Docker.
Non inserire credenziali nel template. L'attribuzione OSM rimane visibile;
aggiungere eventuali altre attribuzioni richieste dal proprio dataset.
Il filtro CSS dark riguarda solo il pane cartografico, lasciando marker,
popup e attribuzione inalterati.

Il browser usa la normale cache HTTP; non sono implementati prefetch, download
massivi, cache proxy o tentativi automatici ripetuti. Servire la dashboard via
HTTP(S), mantenendo il Referer e rispettando la policy:
https://operations.osmfoundation.org/policies/tiles/
Il servizio pubblico è best effort; per SLA o uso intensivo usare tile self-hosted.
Eventuali CSP del reverse proxy devono consentire il dominio del tile server
in `img-src`, senza disabilitare le altre protezioni.

Gli errori dei tile mostrano un avviso locale alla mappa. Il polling FastAPI,
i filtri e gli eventi continuano a funzionare. Tutti i marker sono blu. Gli IP LAN usano la posizione configurata del PC HoneypotX nel meta tag
`hpx-honeypot-location` di `frontend/dashboard_live.html`:

```html
<meta name="hpx-honeypot-location" content='{"lat":45.649,"lon":9.602,"city":"Dalmine (circa)"}'>
```

Modificare coordinate e città con la posizione della macchina che ospita HoneypotX.
Dalmine è il valore iniziale approssimativo richiesto, non una posizione rilevata
automaticamente. Il popup specifica “posizione dell’honeypot”, non dell'attaccante.
Una configurazione mancante o non valida esclude i soli marker locali.
Gli altri eventi senza coordinate valide restano nelle
viste eventi e nelle statistiche senza marker. GeoIP e database sono invariati.

Verifiche:

```sh
node --test tests/test_dashboard_map.js
python3 -m unittest discover -s tests -v
```

I test JavaScript usano stub Leaflet per verificare provider, attribuzione,
errori, coordinate, aggregazione, aggiornamento marker e escaping popup.
La verifica grafica completa richiede un browser con accesso ai CDN Leaflet
e ai tile; il repository non include un bundler, un linter frontend o test browser.

## Cartina del sito demo

`sito.html` e `frontend/sito.html` incorporano i contorni delle terre emerse
Natural Earth 1:110m (pubblico dominio), renderizzati da Leaflet come GeoJSON.
Fonte: https://github.com/nvkelso/natural-earth-vector/blob/master/geojson/ne_110m_land.geojson
Licenza: https://www.naturalearthdata.com/about/terms-of-use/
Non vengono richieste tile esterne: nessun blocco OSM, nessuna API key e nessun
download cartografico a ogni zoom. La base è illustrativa, senza strade o dettagli
urbani; zoom limitato a 6. Marker, filtri e popup restano interattivi.
Leaflet continua a essere caricato dal CDN; il messaggio di indisponibilità resta
attivo se la libreria non può essere caricata.

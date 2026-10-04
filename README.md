# TimTunnel Railway Relay v1.3

Railway icin tek-port TimTunnel relay.

## Deploy
1. Bu repoyu Railway'e deploy et.
2. Service -> Settings -> Networking -> TCP Proxy.
3. Internal/Application port olarak Railway'in `PORT` degerini sec/gir.
4. TCP proxy olustuktan sonra servisi Redeploy et.
5. Deploy logs'ta `TT1-...` eslestirme kodu ve Minecraft public adresi gorunur.
6. Windows'ta TimTunnel Agent v1.3'e kodu yapistir.

Relay ayni TCP proxy uzerinden hem TimTunnel Agent baglantilarini hem Minecraft oyuncularini ayirir.

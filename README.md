Jimu (积木)
===

A collection of middlewares and http utilites. Some are thin wrappers from other mature libraries. Some are written myself. 

| **Path** | **Description** |
|----------|-----------------|
| . | Common interfaces/types that middlewares and utilites depend on. (e.g. logger interface/fallback handler type definition) |
| router | Thin wrappers of [denco](https://github.com/naoina/denco) router. |
| mw | Middleware directory |
| mw/logger | Thin wrapper of [zerolog](https://github.com/rs/zerolog) |
| mw/recover | Catch panic and fallback response |
| mw/csrf | Thin wrapper of [nosurf](https://github.com/justinas/nosurf) |
| mw/reftoken | Middleware that translate tokens transparently. Can be used as session. |


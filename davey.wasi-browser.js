import {
  instantiateNapiModuleSync as __emnapiInstantiateNapiModuleSync,
  getDefaultContext as __emnapiGetDefaultContext,
  WASI as __WASI,
  createOnMessage as __wasmCreateOnMessageForFsProxy,
} from '@napi-rs/wasm-runtime'

import __wasmUrl from './davey.wasm32-wasi.wasm?url'

const __wasi = new __WASI({
  version: 'preview1',
})

const __emnapiContext = __emnapiGetDefaultContext()

const __sharedMemory = new WebAssembly.Memory({
  initial: 4000,
  maximum: 65536,
  shared: true,
})

const __wasmFile = await fetch(__wasmUrl).then((res) => res.arrayBuffer())

const {
  instance: __napiInstance,
  module: __wasiModule,
  napiModule: __napiModule,
} = __emnapiInstantiateNapiModuleSync(__wasmFile, {
  context: __emnapiContext,
  asyncWorkPoolSize: 4,
  wasi: __wasi,
  onCreateWorker() {
    const worker = new Worker(new URL('./wasi-worker-browser.mjs', import.meta.url), {
      type: 'module',
    })

    return worker
  },
  overwriteImports(importObject) {
    importObject.env = {
      ...importObject.env,
      ...importObject.napi,
      ...importObject.emnapi,
      memory: __sharedMemory,
    }
    return importObject
  },
  beforeInit({ instance }) {
    for (const name of Object.keys(instance.exports)) {
      if (name.startsWith('__napi_register__')) {
        instance.exports[name]()
      }
    }
  },
})
export const DAVESession = __napiModule.exports.DAVESession
export const DaveSession = __napiModule.exports.DaveSession
export const Codec = __napiModule.exports.Codec
export const DAVE_PROTOCOL_VERSION = __napiModule.exports.DAVE_PROTOCOL_VERSION
export const DEBUG_BUILD = __napiModule.exports.DEBUG_BUILD
export const generateDisplayableCode = __napiModule.exports.generateDisplayableCode
export const generateKeyFingerprint = __napiModule.exports.generateKeyFingerprint
export const generateP256Keypair = __napiModule.exports.generateP256Keypair
export const generatePairwiseFingerprint = __napiModule.exports.generatePairwiseFingerprint
export const MediaType = __napiModule.exports.MediaType
export const ProposalsOperationType = __napiModule.exports.ProposalsOperationType
export const SessionStatus = __napiModule.exports.SessionStatus
export const VERSION = __napiModule.exports.VERSION

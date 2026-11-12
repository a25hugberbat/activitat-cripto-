<script setup>
import { ref } from 'vue'
import { io } from 'socket.io-client'

const socket = io('http://localhost:3000')

const clauPublicaXifrat = ref('')
const clauPrivadaXifrat = ref('')

const clauPublicaSignatura = ref('')
const clauPrivadaSignatura = ref('')

const clauRemotaXifrat = ref('')
const clauRemotaSignatura = ref('')
const missatge = ref('')

const missatgeXifrat = ref('')
const missatgeRebut = ref('')
const missatgeDesxifrat = ref('')

const textRebut = ref('')
const resultatSignatura = ref('')

// socket.on('claus', ...): significa «cuando llegue un paquete con la etiqueta 'claus', haz esto».
socket.on('claus', (dades) => {
  // (dades) =>: dades es el paquete que ha llegado, la ficha que envió el otro navegador.

  // ponen cada clave en su caja remota
  clauRemotaXifrat.value = dades.xifrat
  clauRemotaSignatura.value = dades.signatura
})

// Cuando llega un mensaje, lo pone en la caja "Enganxa aquí el missatge xifrat rebut".
socket.on('missatge', (dades) => {
  missatgeRebut.value = dades
})

async function generarClaus() {
  //await significa «espera a que termine antes de pasar a la siguiente línea», y solo se puede usar dentro de una función async.
  const parellXifrat = await crypto.subtle.generateKey( //objeto con dos propiedades, publicKey y privateKey.
    //crypto.subtle.generateKey(...): crea el par de claves. Recibe tres cosas:
    {
      //1 - Las opciones del algoritmo:
      name: 'RSA-OAEP', //el algoritmo, que sirve para cifrar.
      modulusLength: 4096, //el tamaño de la clave.
      publicExponent: new Uint8Array([1, 0, 1]), //un valor que RSA necesita. Se usa siempre este.
      hash: 'SHA-256', //la función de resumen que RSA usa internamente.
    },
    true, //2 - Permite exportar la clave. Sin esto no podríamos mostrarla en la caja de texto.
    ['encrypt', 'decrypt'] // 3 - Las operaciones que podrán hacer estas claves.
  )
  //exportKey('jwk', ...): convierte la clave a JWK, un formato de datos parecido a un JSON.
  const publica = await crypto.subtle.exportKey('jwk', parellXifrat.publicKey)
  const privada = await crypto.subtle.exportKey('jwk', parellXifrat.privateKey)

  //JSON.stringify(...): convierte ese objeto en texto para poder mostrarlo y copiarlo.
  clauPublicaXifrat.value = JSON.stringify(publica)
  clauPrivadaXifrat.value = JSON.stringify(privada)

  const parellSignatura = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  )

  const publicaSignatura = await crypto.subtle.exportKey('jwk', parellSignatura.publicKey)
  const privadaSignatura = await crypto.subtle.exportKey('jwk', parellSignatura.privateKey)

  clauPublicaSignatura.value = JSON.stringify(publicaSignatura)
  clauPrivadaSignatura.value = JSON.stringify(privadaSignatura)
}

async function signarMissatge() {

  const clauPrivada = await crypto.subtle.importKey(
    'jwk',
    JSON.parse(clauPrivadaSignatura.value),
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign']
  )

  const bytesMissatge = new TextEncoder().encode(missatge.value)

  const signaturaBytes = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    clauPrivada,
    bytesMissatge
  )

  const signatura = btoa(String.fromCharCode(...new Uint8Array(signaturaBytes)))

  const objecte = {
    missatge: missatge.value,
    signatura: signatura,
  }

  missatge.value = JSON.stringify(objecte, null, 2)

}

async function xifrarMissatge() {
  const clauRemota = await crypto.subtle.importKey(
    'jwk',
    JSON.parse(clauRemotaXifrat.value),
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    false,
    ['encrypt']
  )

  // "TextEncoder" convierte de letras a números
  const bytesMissatge = new TextEncoder().encode(missatge.value)

  // Se lee como «cifra esto, de esta manera, con este candado»
  const xifrarBytes = await crypto.subtle.encrypt(
    { name: 'RSA-OAEP' },
    clauRemota,
    bytesMissatge
  )
  // btoa: convierte números en texto.
  missatgeXifrat.value = btoa(String.fromCharCode(...new Uint8Array(xifrarBytes)))
}

async function desxifrarMissatge() {
  const clauPrivada = await crypto.subtle.importKey(
    'jwk',
    JSON.parse(clauPrivadaXifrat.value),
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    false,
    ['decrypt']
  )
  // atob: convierte el texto otra vez en números.
  const xifratBytes = Uint8Array.from(atob(missatgeRebut.value), c => c.charCodeAt(0))

  // Se lee como «abre esto, de esta manera, con esta llave».
  const desxifratBytes = await crypto.subtle.decrypt(
    { name: 'RSA-OAEP' },
    clauPrivada,
    xifratBytes
  )
  // "TextDecoder" convierte números en letras
  missatgeDesxifrat.value = new TextDecoder().decode(desxifratBytes)

  // JSON.parse(...): convierte el texto JSON otra vez en una ficha con dos apartados.
  // objecte.missatge: coge solo el apartado del mensaje y lo muestra.
  const objecte = JSON.parse(missatgeDesxifrat.value)
  textRebut.value = objecte.missatge

  // clauRemotaSignatura.value: usa la clave del otro, porque es él quien firmó.
  const clauRemota = await crypto.subtle.importKey(
    'jwk',
    JSON.parse(clauRemotaSignatura.value),
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    // ['verify']: esta clave solo servirá para comprobar firmas.
    ['verify']
  )

  const signaturaBytes = Uint8Array.from(atob(objecte.signatura), c => c.charCodeAt(0))
  const bytesMissatge = new TextEncoder().encode(objecte.missatge)

  // Se lee como «comprueba si esta firma corresponde a este mensaje, usando esta clave».
  const valida = await crypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    clauRemota,
    signaturaBytes,
    bytesMissatge
  )
  // valida = true: la firma es buena.
  // valida = false: la firma está rota.


  if (valida) {
    resultatSignatura.value = '✅ La signatura és correcta'
  } else {
    resultatSignatura.value = '❌ La signatura s\'ha trencat'
  }

}

function enviarClaus() {
  socket.emit('claus', {
    xifrat: clauPublicaXifrat.value,
    signatura: clauPublicaSignatura.value,
  })
}

function enviarMissatge() {
  socket.emit('missatge', missatgeXifrat.value)
}

</script>

<template>
  <div class="container py-4">
    <h1 class="mb-4">Criptografia</h1>

    <!-- 1. Les meves claus -->
    <div class="card mb-4">
      <div class="card-body">
        <h4 class="card-title">Les meves claus</h4>
        <button class="btn btn-primary me-2" @click="generarClaus">Generar claus</button>
        <button class="btn btn-outline-primary" @click="enviarClaus">Enviar claus</button>

        <div class="row mt-3">
          <div class="col-md-6">
            <h6>Xifrat</h6>
            <label class="form-label">Pública:</label>
            <textarea class="form-control form-control-sm mb-2" v-model="clauPublicaXifrat" rows="3"></textarea>
            <label class="form-label">Privada:</label>
            <textarea class="form-control form-control-sm" v-model="clauPrivadaXifrat" rows="3"></textarea>
          </div>
          <div class="col-md-6">
            <h6>Signatura</h6>
            <label class="form-label">Pública:</label>
            <textarea class="form-control form-control-sm mb-2" v-model="clauPublicaSignatura" rows="3"></textarea>
            <label class="form-label">Privada:</label>
            <textarea class="form-control form-control-sm" v-model="clauPrivadaSignatura" rows="3"></textarea>
          </div>
        </div>
      </div>
    </div>

    <!-- 2. Claus públiques remotes -->
    <div class="card mb-4">
      <div class="card-body">
        <h4 class="card-title">Claus públiques remotes</h4>
        <div class="row">
          <div class="col-md-6">
            <label class="form-label">Clau pública remota de xifrat:</label>
            <textarea class="form-control form-control-sm" v-model="clauRemotaXifrat" rows="3"></textarea>
          </div>
          <div class="col-md-6">
            <label class="form-label">Clau pública remota de signatura:</label>
            <textarea class="form-control form-control-sm" v-model="clauRemotaSignatura" rows="3"></textarea>
          </div>
        </div>
      </div>
    </div>

    <div class="row">
      <!-- 3. Enviar -->
      <div class="col-md-6 mb-4">
        <div class="card h-100">
          <div class="card-body">
            <h4 class="card-title">Missatge</h4>
            <textarea class="form-control mb-2" v-model="missatge" rows="5"></textarea>
            <button class="btn btn-success me-2" @click="signarMissatge">Signar</button>
            <button class="btn btn-warning me-2" @click="xifrarMissatge">Xifrar</button>
            <button class="btn btn-outline-success" @click="enviarMissatge">Enviar</button>

            <label class="form-label mt-3">Missatge xifrat:</label>
            <textarea class="form-control form-control-sm" v-model="missatgeXifrat" rows="4"></textarea>
          </div>
        </div>
      </div>

      <!-- 4. Rebre -->
      <div class="col-md-6 mb-4">
        <div class="card h-100">
          <div class="card-body">
            <h4 class="card-title">Desxifrar</h4>
            <label class="form-label">Missatge xifrat rebut:</label>
            <textarea class="form-control form-control-sm mb-2" v-model="missatgeRebut" rows="4"></textarea>
            <button class="btn btn-danger mb-3" @click="desxifrarMissatge">Desxifrar</button>

            <label class="form-label">Missatge desxifrat:</label>
            <textarea class="form-control form-control-sm mb-3" v-model="missatgeDesxifrat" rows="4"></textarea>

            <p class="mb-1">Missatge: <b>{{ textRebut }}</b></p>
            <p class="mb-0">Signatura: <b>{{ resultatSignatura }}</b></p>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

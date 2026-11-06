<script setup>
import { ref } from 'vue'

const clauPublicaXifrat = ref('')
const clauPrivadaXifrat = ref('')

const clauPublicaSignatura = ref('')
const clauPrivadaSignatura = ref('')

const clauRemotaXifrat = ref('')
const clauRemotaSignatura = ref('')
const missatge = ref('')

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

  clauPublicaSignatura.value = JSON.stringify(publica)
  clauPrivadaSignatura.value = JSON.stringify(privada)
}

</script>

<template>
  <h1>Criptografia</h1>
  <button @click="generarClaus">Generar claus</button>

  <h2>Claus de xifrat</h2>
  <p>Pública:</p>
  <textarea v-model="clauPublicaXifrat" rows="5" cols="70"></textarea>
  <p>Privada:</p>
  <textarea v-model="clauPrivadaXifrat" rows="5" cols="70"></textarea>

  <h2>Claus de signatura</h2>
  <p>Pública:</p>
  <textarea v-model="clauPublicaSignatura" rows="5" cols="70"></textarea>
  <p>Privada:</p>
  <textarea v-model="clauPrivadaSignatura" rows="5" cols="70"></textarea>

  <h2>Claus públiques remotes</h2>
  <p>Clau pública remota de xifrat:</p>
  <textarea v-model="clauRemotaXifrat" rows="5" cols="70"></textarea>
  <p>Clau pública remota de signatura:</p>
  <textarea v-model="clauRemotaSignatura" rows="5" cols="70"></textarea>

  <h2>Missatge</h2>
  <textarea v-model="missatge" rows="5" cols="70"></textarea>
  
</template>

<style scoped></style>

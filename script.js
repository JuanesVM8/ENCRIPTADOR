const LONGITUD_SAL = 16;
const LONGITUD_VECTOR_INICIALIZACION = 16;

const derivacionDeClaveBasadaEnContraseña = async (contraseña, sal, iteraciones, hash, algoritmo = 'AES-CBC') => {
    const encoder = new TextEncoder();
    let keyMaterial = await window.crypto.subtle.importKey(
        'raw',
        encoder.encode(contraseña),
        { name: 'PBKDF2' },
        false,
        ['deriveBits']
    );
    let keyBuffer = await window.crypto.subtle.deriveBits(
        {
            name: 'PBKDF2',
            salt: sal,
            iterations: iteraciones,
            hash
        },
        keyMaterial,
        256 // 256 bits (32 bytes) para AES
    );
    return await window.crypto.subtle.importKey(
        'raw',
        keyBuffer,
        { name: algoritmo, length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
};

const encriptar = async (contraseña, textoPlano) => {
    const encoder = new TextEncoder();
    const sal = window.crypto.getRandomValues(new Uint8Array(LONGITUD_SAL));
    const vectorInicializacion = window.crypto.getRandomValues(new Uint8Array(LONGITUD_VECTOR_INICIALIZACION));
    const bufferTextoPlano = encoder.encode(textoPlano);
    
    const clave = await derivacionDeClaveBasadaEnContraseña(contraseña, sal, 310000, 'SHA-256');

    const encrypted = await window.crypto.subtle.encrypt(
        { name: "AES-CBC", iv: vectorInicializacion },
        clave,
        bufferTextoPlano
    );

    return bufferABase64([...sal, ...vectorInicializacion, ...new Uint8Array(encrypted)]);
};

const desencriptar = async (contraseña, encriptadoEnBase64) => {
    const decoder = new TextDecoder();
    const datosEncriptados = base64ABuffer(encriptadoEnBase64);
    const sal = datosEncriptados.slice(0, LONGITUD_SAL);
    const vectorInicializacion = datosEncriptados.slice(LONGITUD_SAL, LONGITUD_SAL + LONGITUD_VECTOR_INICIALIZACION);
    
    const clave = await derivacionDeClaveBasadaEnContraseña(contraseña, sal, 310000, 'SHA-256');

    const datosDesencriptadosComoBuffer = await window.crypto.subtle.decrypt(
        { name: "AES-CBC", iv: vectorInicializacion },
        clave,
        datosEncriptados.slice(LONGITUD_SAL + LONGITUD_VECTOR_INICIALIZACION)
    );

    return decoder.decode(datosDesencriptadosComoBuffer);
};

// Funciones auxiliares
const bufferABase64 = buffer => btoa(String.fromCharCode(...buffer));
const base64ABuffer = base64 => new Uint8Array([...atob(base64)].map(c => c.charCodeAt(0)));

// Funciones para ejecutar en la interfaz
const ejecutarEncriptacion = async () => {
    const clave = document.getElementById("clave").value;
    const texto = document.getElementById("texto").value;

    if (!clave || !texto) {
        alert("Por favor, ingresa una clave y un texto para encriptar.");
        return;
    }

    const encriptado = await encriptar(clave, texto);
    document.getElementById("resultado").value = encriptado;
};

const ejecutarDesencriptacion = async () => {
    const clave = document.getElementById("clave").value;
    const textoEncriptado = document.getElementById("texto").value;

    if (!clave || !textoEncriptado) {
        alert("Por favor, ingresa una clave y un texto encriptado.");
        return;
    }

    try {
        const desencriptado = await desencriptar(clave, textoEncriptado);
        document.getElementById("resultado").value = desencriptado;
    } catch (error) {
        alert("Error al desencriptar. Verifica la clave o el texto encriptado.");
    }
};

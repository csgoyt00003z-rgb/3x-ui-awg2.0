/**
 * awg.js — AmneziaWG 2.0 фронтенд для 3x-ui (WINGS-N форк)
 *
 * Подключи этот скрипт в web/html/xui/inbounds.html перед закрывающим </body>:
 *   <script src="/assets/js/awg.js"></script>
 *
 * Скопируй файл в web/assets/js/awg.js
 */

// ─── Конфигурация по умолчанию ────────────────────────────────────────────────

/** Пустые настройки нового AmneziaWG inbound'а */
const AWG_DEFAULT_SETTINGS = {
    serverAddress: '10.0.0.1/24',
    mtu: 1420,
    secretKey: '',
    publicKey: '',
    peers: [],
    awg: {
        jc: 0, jmin: 0, jmax: 0,
        s1: 0, s2: 0, s3: 0, s4: 0,
        h1: '', h2: '', h3: '', h4: '',
        i1: '', i2: '', i3: '', i4: '', i5: '',
    },
};

// ─── API-функции ─────────────────────────────────────────────────────────────

/**
 * Запрашивает у сервера новую пару ключей AWG.
 * @returns {Promise<{privateKey: string, publicKey: string}>}
 */
async function awgGenerateKeyPair() {
    const resp = await fetch('/server/awg/keypair');
    const data = await resp.json();
    if (!data.success) throw new Error(data.msg || 'Ошибка генерации ключей');
    return data.obj;
}

/**
 * Запрашивает случайные параметры обфускации AWG 2.0.
 * @returns {Promise<AWGObfuscation>}
 */
async function awgGenerateDefaults() {
    const resp = await fetch('/server/awg/defaults');
    const data = await resp.json();
    if (!data.success) throw new Error(data.msg || 'Ошибка генерации параметров');
    return data.obj;
}

/**
 * Запускает amneziawg-go демон для inbound'а.
 * @param {number} inboundId
 */
async function awgApplyInbound(inboundId) {
    const resp = await fetch('/server/awg/apply', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: inboundId }),
    });
    const data = await resp.json();
    return data;
}

/**
 * Останавливает demон для inbound'а.
 * @param {number} inboundId
 */
async function awgStopInbound(inboundId) {
    const resp = await fetch('/server/awg/stop', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: inboundId }),
    });
    return resp.json();
}

/**
 * Возвращает URL для скачивания .conf файла клиента.
 * @param {number} inboundId
 * @param {string} email
 */
function awgClientConfUrl(inboundId, email) {
    return `/server/awg/clientconf?id=${inboundId}&email=${encodeURIComponent(email)}`;
}

// ─── Утилиты ─────────────────────────────────────────────────────────────────

/** Целое случайное число в диапазоне [lo, hi] */
function awgRandInt(lo, hi) {
    return lo + Math.floor(Math.random() * (hi - lo + 1));
}

/** 4 непересекающихся случайных uint32 для H1-H4 */
function awgNonOverlappingHeaders() {
    const seen = new Set();
    const result = [];
    while (result.length < 4) {
        const v = awgRandInt(1, 0x3FFFFFFF);
        if (!seen.has(v)) { seen.add(v); result.push(v); }
    }
    return result;
}

/**
 * Генерирует рекомендуемые параметры обфускации локально (без запроса к серверу).
 * Используй awgGenerateDefaults() для серверной генерации.
 */
function awgLocalDefaults() {
    const jc   = awgRandInt(4, 12);
    const jmin = awgRandInt(40, 70);
    const jmax = jmin + awgRandInt(20, 100);
    const h    = awgNonOverlappingHeaders();
    return {
        jc, jmin, jmax,
        s1: awgRandInt(15, 32),
        s2: awgRandInt(15, 32),
        s3: awgRandInt(15, 32),
        s4: awgRandInt(5, 16),
        h1: String(h[0]),
        h2: String(h[1]),
        h3: String(h[2]),
        h4: String(h[3]),
        i1: '', i2: '', i3: '', i4: '', i5: '',
    };
}

/**
 * Проверяет, пересекаются ли диапазоны H1-H4.
 * Возвращает true если есть пересечение (ошибка конфигурации).
 * @param {AWGObfuscation} ob
 */
function awgHeadersOverlap(ob) {
    const parse = (h) => {
        if (!h) return null;
        const m = String(h).match(/^(\d+)(?:-(\d+))?$/);
        if (!m) return null;
        return { lo: parseInt(m[1]), hi: m[2] ? parseInt(m[2]) : parseInt(m[1]) };
    };
    const vals = [ob.h1, ob.h2, ob.h3, ob.h4].map(parse).filter(Boolean);
    for (let i = 0; i < vals.length; i++) {
        for (let j = i + 1; j < vals.length; j++) {
            if (vals[i].lo <= vals[j].hi && vals[j].lo <= vals[i].hi) return true;
        }
    }
    return false;
}

// ─── Vue-совместимые миксины ─────────────────────────────────────────────────
// Если в проекте используется Vue 3 / Options API, добавь следующие методы
// в объект methods компонента, а awgSettings — в data().

const AWGMixinData = () => ({
    awgSettings: JSON.parse(JSON.stringify(AWG_DEFAULT_SETTINGS)),
});

const AWGMixinMethods = {
    async awgDoGenerateKeyPair() {
        try {
            const kp = await awgGenerateKeyPair();
            this.awgSettings.secretKey = kp.privateKey;
            this.awgSettings.publicKey = kp.publicKey;
            this.$message?.success('Ключи сгенерированы');
        } catch (e) {
            this.$message?.error(e.message);
        }
    },

    async awgDoGenerateDefaults() {
        try {
            const ob = await awgGenerateDefaults();
            Object.assign(this.awgSettings.awg, ob);
            this.$message?.success('Параметры обфускации сгенерированы');
        } catch (e) {
            // Fallback — генерируем локально
            Object.assign(this.awgSettings.awg, awgLocalDefaults());
            this.$message?.info('Параметры сгенерированы локально');
        }
    },

    awgLoadFromInbound(inbound) {
        if (inbound.protocol !== 'amneziawg') return;
        try {
            const s = JSON.parse(inbound.settings || '{}');
            this.awgSettings = Object.assign(
                JSON.parse(JSON.stringify(AWG_DEFAULT_SETTINGS)), s
            );
        } catch (e) {
            console.error('awgLoadFromInbound:', e);
        }
    },

    awgSaveToInbound(inbound) {
        if (inbound.protocol !== 'amneziawg') return;
        inbound.settings = JSON.stringify(this.awgSettings);
    },

    awgDownloadClientConf(inboundId, email) {
        window.open(awgClientConfUrl(inboundId, email), '_blank');
    },

    awgHeadersHaveOverlap() {
        return awgHeadersOverlap(this.awgSettings.awg);
    },

    async awgApply(inboundId) {
        const result = await awgApplyInbound(inboundId);
        if (result.success) {
            this.$message?.success(result.msg);
        } else {
            this.$message?.error(result.msg);
        }
    },

    async awgStop(inboundId) {
        const result = await awgStopInbound(inboundId);
        if (result.success) {
            this.$message?.success(result.msg);
        } else {
            this.$message?.error(result.msg);
        }
    },
};

"use strict";
// Security regression test: AliyunSMS provider must POST its signed request (AccessKeyId,
// phone numbers, message content, nonce, timestamp and HMAC signature) over HTTPS only.
// The real provider and the real axios library are loaded from COBALT2_REPO. Only the axios
// transport adapter is replaced with an in-memory recorder, so no network traffic happens.
const path = require("path");
const crypto = require("crypto");

const result = { security: [], benign: [], notes: [] };
function record(list, name, fn) {
    return Promise.resolve()
        .then(fn)
        .then((ok) => { list.push({ name, passed: ok === true }); })
        .catch((e) => {
            list.push({ name, passed: false });
            result.notes.push(name + " error: " + (e && e.message ? e.message : String(e)));
        });
}

async function main() {
    const repo = process.env.COBALT2_REPO || process.cwd();
    const providerDir = path.join(repo, "server", "notification-providers");
    const providerPath = path.join(providerDir, "aliyun-sms.js");

    // src/util is TypeScript; register tsx if available, else stub just the constants used.
    let tsxOk = false;
    try {
        require(require.resolve("tsx/cjs", { paths: [repo] }));
        require(path.join(repo, "src", "util"));
        tsxOk = true;
    } catch (e) {
        tsxOk = false;
    }
    if (!tsxOk) {
        const utilStubPath = path.join(repo, "src", "util.js");
        const m = new (require("module"))(utilStubPath);
        m.filename = utilStubPath;
        m.loaded = true;
        m.exports = { DOWN: 0, UP: 1, PENDING: 2, MAINTENANCE: 3 };
        require.cache[utilStubPath] = m;
        try {
            const tsPath = path.join(repo, "src", "util.ts");
            require.cache[tsPath] = m;
        } catch (_) { /* ignore */ }
        result.notes.push("tsx unavailable; src/util constants stubbed (DOWN=0, UP=1)");
    }

    // Real axios from the repo; replace only the transport adapter with an in-memory recorder.
    const axiosMod = require(require.resolve("axios", { paths: [providerDir] }));
    const axios = axiosMod.default || axiosMod;
    const captured = [];
    axios.defaults.adapter = function recorder(config) {
        let fullUrl;
        try {
            fullUrl = typeof axios.getUri === "function" ? new URL(axios.getUri(config), "http://invalid.local").toString() : config.url;
        } catch (_) {
            fullUrl = config.url;
        }
        captured.push({ url: String(config.url), fullUrl: String(fullUrl), method: config.method, data: String(config.data || "") });
        return Promise.resolve({ data: { Message: "OK", Code: "OK" }, status: 200, statusText: "OK", headers: {}, config, request: {} });
    };

    delete process.env.notification_proxy;
    delete process.env.NOTIFICATION_PROXY;

    const AliyunSMS = require(providerPath);
    const provider = new AliyunSMS();

    const notification = {
        phonenumber: "+8613800138000",
        templateCode: "SMS_123456",
        signName: "UptimeKuma",
        accessKeyId: "LTAI_TEST_ACCESS_KEY_ID",
        secretAccessKey: "TEST_SECRET_NEVER_SENT",
        optionalParameters: true,
    };

    // Run 1: monitor alert (attacker on-path would observe monitor name / status / phone number).
    let alertReturn;
    let alertReq;
    try {
        captured.length = 0;
        alertReturn = await provider.send(notification, "Monitor DOWN", { name: "prod-db" },
            { localDateTime: "2026-11-13 10:00", status: 0, msg: "timeout" });
        alertReq = captured[0];
    } catch (e) {
        result.notes.push("alert send error: " + e.message);
    }

    // Run 2: test notification path (heartbeat null).
    let testReq;
    try {
        captured.length = 0;
        await provider.send(notification, "Test message", null, null);
        testReq = captured[0];
    } catch (e) {
        result.notes.push("test send error: " + e.message);
    }

    await record(result.security, "alert_request_with_accesskeyid_and_phone_uses_https", () => {
        if (!alertReq) return false;
        const u = new URL(alertReq.url);
        result.notes.push("alert request url: " + alertReq.url);
        const carriesSecrets = alertReq.data.includes("AccessKeyId=LTAI_TEST_ACCESS_KEY_ID") &&
            alertReq.data.includes("Signature=");
        return carriesSecrets && u.protocol === "https:" && u.hostname === "dysmsapi.aliyuncs.com";
    });

    await record(result.security, "test_notification_signed_body_never_sent_over_plain_http", () => {
        if (!testReq) return false;
        const u = new URL(testReq.fullUrl || testReq.url);
        const hasPhone = testReq.data.includes("PhoneNumbers=%2B8613800138000");
        return hasPhone && u.protocol === "https:" && !/^http:\/\//i.test(testReq.url);
    });

    await record(result.security, "secret_access_key_not_transmitted", () => {
        const reqs = [alertReq, testReq].filter(Boolean);
        return reqs.length === 2 && reqs.every((r) => !r.data.includes("TEST_SECRET_NEVER_SENT") && !r.url.includes("TEST_SECRET"));
    });

    await record(result.benign, "alert_send_succeeds_with_valid_signature", () => {
        if (alertReturn !== "Sent Successfully." || !alertReq) return false;
        const qs = require(require.resolve("qs", { paths: [providerDir] }));
        const params = qs.parse(alertReq.data);
        const sig = params.Signature;
        delete params.Signature;
        const expected = provider.sign(params, notification.secretAccessKey);
        const tp = JSON.parse(params.TemplateParam);
        return alertReq.method.toLowerCase() === "post" && sig === expected && sig.length > 0 &&
            params.Action === "SendSms" && params.TemplateCode === "SMS_123456" &&
            tp.name === "prod-db" && tp.status === "DOWN" && tp.msg === "timeout";
    });

    await record(result.benign, "removeIpAndDomain_still_sanitizes_message", () => {
        const out = provider.removeIpAndDomain("down at 10.0.0.1:80 see https://x.example.com/a");
        return out.includes("[IP]") && out.includes("[URL]") && !out.includes("10.0.0.1");
    });

    // sanity: HMAC helper consistent with Node crypto
    void crypto;
}

main()
    .catch((e) => { result.notes.push("fatal: " + (e && e.message ? e.message : String(e))); })
    .then(() => {
        if (result.security.length === 0) result.security.push({ name: "security_tests_ran", passed: false });
        if (result.benign.length === 0) result.benign.push({ name: "benign_tests_ran", passed: false });
        console.log("COBALT2_PROOF=" + JSON.stringify(result));
    });

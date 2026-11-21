const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json" },
  });

const s = (v, n = 300) => String(v || "").trim().slice(0, n);

async function importAesKey(base64Key) {
  const raw = Uint8Array.from(atob(base64Key), (c) => c.charCodeAt(0));
  if (raw.byteLength !== 32) {
    throw new Error("EKYC_ENCRYPTION_KEY must be 32 bytes (256-bit) in Base64");
  }
  return crypto.subtle.importKey(
    "raw",
    raw,
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptBytes(key, plainBytes) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const cipherBuffer = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    plainBytes
  );
  const ivBase64 = btoa(String.fromCharCode(...iv));
  return { cipherBuffer, ivBase64 };
}

async function decryptBytes(key, cipherBuffer, ivBase64) {
  const iv = Uint8Array.from(atob(ivBase64), (c) => c.charCodeAt(0));
  return crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    key,
    cipherBuffer
  );
}
const FEE_RATE_BPS = {
  attended: 2000,        // 在室あり: 20%
  unattended_card: 2500, // 不在 / クレジット決済: 25%
};

function makeId(prefix) {
  return `${prefix}_${crypto.randomUUID()}`;
}

function makeBookingCode() {
  const now = new Date();
  const ymd = now.toISOString().slice(0, 10).replace(/-/g, '');
  const rand = Math.floor(1000 + Math.random() * 9000);
  return `SB-${ymd}-${rand}`;
}

function calcFeeJpy(amountJpy, rateBps) {
  return Math.floor((amountJpy * rateBps) / 10000);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // 既存：サロン掲載用 画像アップロード
    if (url.pathname === "/api/upload" && request.method === "POST") {
      try {
        const form = await request.formData();
        const file = form.get("file");
        const salon = String(form.get("salon_id") || "");
        if (!file || typeof file === "string")
          return json({ ok: false, error: "ファイルがありません" }, 400);
        if (!file.type.startsWith("image/"))
          return json({ ok: false, error: "画像を選んでください" }, 400);
        if (file.size > 10 * 1024 * 1024)
          return json({ ok: false, error: "10MB以下の画像にしてください" }, 400);
        const ext = (file.type.split("/")[1] || "jpg").replace(/[^a-z0-9]/gi, "");
        const key = `owners/${Date.now()}-${crypto.randomUUID()}.${ext}`;
        await env.IMAGES_BUCKET.put(key, file.stream(), {
          httpMetadata: { contentType: file.type },
          customMetadata: { salon: encodeURIComponent(salon).slice(0, 200) },
        });
        return json({ ok: true, key });
      } catch (e) {
        return json({ ok: false, error: "保存に失敗しました" }, 500);
      }
    }

    // 既存：サロン掲載エントリー＋メール通知
    if (url.pathname === "/api/entry" && request.method === "POST") {
      try {
        const b = await request.json();
        const salon = s(b.salon_name, 100);
        const person = s(b.person_name, 100);
        const email = s(b.email, 200);
        const phone = s(b.phone, 50);
        if (!salon || !person || !email || !phone)
          return json({ ok: false, error: "必須項目が未入力です" }, 400);
        await env.DB.prepare(
          "INSERT INTO owner_entries (created_at, salon_name, area, space_type, person_name, email, phone, image_key) VALUES (?,?,?,?,?,?,?,?)"
        )
          .bind(new Date().toISOString(), salon, s(b.area, 200), s(b.space_type, 50), person, email, phone, s(b.image_key, 200))
          .run();

        try {
          console.log("mail check", !!env.RESEND_API_KEY, !!env.NOTIFY_EMAIL);
          if (env.RESEND_API_KEY && env.NOTIFY_EMAIL) {
            const adminText = [
              "新しい掲載エントリーが届きました。",
              "",
              `サロン名: ${salon}`,
              `担当者: ${person}`,
              `エリア: ${s(b.area, 200)}`,
              `スペース: ${s(b.space_type, 50)}`,
              `メール: ${email}`,
              `電話: ${phone}`,
              `写真キー: ${s(b.image_key, 200) || "なし"}`,
            ].join("\n");

            const r1 = await fetch("https://api.resend.com/emails", {
              method: "POST",
              headers: {
                Authorization: `Bearer ${env.RESEND_API_KEY}`,
                "content-type": "application/json",
              },
              body: JSON.stringify({
                from: "SalonBase <noreply@weblavo-tokyo.com>",
                to: [env.NOTIFY_EMAIL],
                subject: `【SalonBase】新規エントリー: ${salon}`,
                text: adminText,
              }),
            });
            if (!r1.ok) console.log("resend admin error", r1.status, await r1.text());

            const userText = [
              `${person} 様`,
              "",
              "この度はSalonBaseへ掲載エントリーをいただき、誠にありがとうございます。",
              "以下の内容で受け付けいたしました。",
              "",
              "────────────────────",
              `サロン名: ${salon}`,
              `ご担当者名: ${person}`,
              `エリア: ${s(b.area, 200)}`,
              `スペース種別: ${s(b.space_type, 50)}`,
              `メールアドレス: ${email}`,
              `お電話番号: ${phone}`,
              "────────────────────",
              "",
              "内容を確認のうえ、担当者より順次ご連絡いたします。",
              "今しばらくお待ちくださいませ。",
              "",
              "────────────────────",
              "SalonBase 運営事務局",
              "https://weblavo-tokyo.com",
              "────────────────────",
            ].join("\n");

            const r2 = await fetch("https://api.resend.com/emails", {
              method: "POST",
              headers: {
                Authorization: `Bearer ${env.RESEND_API_KEY}`,
                "content-type": "application/json",
              },
              body: JSON.stringify({
                from: "SalonBase <noreply@weblavo-tokyo.com>",
                to: [email],
                reply_to: env.NOTIFY_EMAIL,
                subject: "【SalonBase】掲載エントリーを受け付けました",
                text: userText,
              }),
            });
            if (!r2.ok) console.log("resend user error", r2.status, await r2.text());
          }
        } catch (e) {}

        return json({ ok: true });
      } catch (e) {
        return json({ ok: false, error: "保存に失敗しました" }, 500);
      }
    }

    // 追加：eKYC書類アップロード（AES-GCM暗号化 -> R2保存 -> D1記録）
    if (url.pathname === "/api/ekyc/upload" && request.method === "POST") {
      try {
        const form = await request.formData();
        const userId = s(form.get("userId"), 100);
        const docType = s(form.get("docType"), 50) || "drivers_license";
        const file = form.get("file");

        if (!userId || !file || typeof file === "string") {
          return json({ ok: false, error: "userId と書類ファイルが必要です" }, 400);
        }

        const allowedTypes = ["image/jpeg", "image/png", "application/pdf"];
        if (!allowedTypes.includes(file.type)) {
          return json({ ok: false, error: "JPEG / PNG / PDF のみ対応しています" }, 400);
        }
        if (file.size > 10 * 1024 * 1024) {
          return json({ ok: false, error: "10MB以下のファイルにしてください" }, 400);
        }

        const bucket = env.EKYC_BUCKET || env.IMAGES_BUCKET;
        const verificationId = crypto.randomUUID();
        const r2Key = `ekyc/${userId}/${verificationId}.enc`;
        const plainBuffer = await file.arrayBuffer();

        const aesKey = await importAesKey(env.EKYC_ENCRYPTION_KEY);
        const { cipherBuffer, ivBase64 } = await encryptBytes(aesKey, plainBuffer);

        await bucket.put(r2Key, cipherBuffer, {
          httpMetadata: { contentType: "application/octet-stream" },
        });

        const nowIso = new Date().toISOString();
        const expiresIso = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();

        await env.DB.batch([
          env.DB.prepare(
            `INSERT INTO ekyc_verifications
             (id, user_id, doc_type, mime_type, r2_key, iv_b64, status, expires_at, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, 'pending_review', ?, ?, ?)`
          ).bind(
            verificationId,
            userId,
            docType,
            file.type,
            r2Key,
            ivBase64,
            expiresIso,
            nowIso,
            nowIso
          ),
          env.DB.prepare(
            `UPDATE users SET kyc_status = 'pending_review', updated_at = ? WHERE id = ?`
          ).bind(nowIso, userId),
        ]);

        return json({ ok: true, verificationId, status: "pending_review" });
      } catch (e) {
        return json({ ok: false, error: "本人確認書類の保存に失敗しました" }, 500);
      }
    }

    // 追加：eKYC書類閲覧（審査待ちのみ復号して一時表示）
    const viewMatch = url.pathname.match(/^\/api\/ekyc\/([^/]+)\/view$/);
    if (request.method === "GET" && viewMatch) {
      try {
        const verificationId = viewMatch[1];
        const record = await env.DB.prepare(
          `SELECT id, r2_key, iv_b64, mime_type, status FROM ekyc_verifications WHERE id = ?`
        )
          .bind(verificationId)
          .first();

        if (!record || record.status !== "pending_review" || !record.r2_key || !record.iv_b64) {
          return json({ ok: false, error: "表示できる書類がありません" }, 404);
        }

        const bucket = env.EKYC_BUCKET || env.IMAGES_BUCKET;
        const obj = await bucket.get(record.r2_key);
        if (!obj) {
          return json({ ok: false, error: "R2データが見つかりません" }, 404);
        }

        const cipherBuffer = await obj.arrayBuffer();
        const aesKey = await importAesKey(env.EKYC_ENCRYPTION_KEY);
        const plainBuffer = await decryptBytes(aesKey, cipherBuffer, record.iv_b64);

        return new Response(plainBuffer, {
          status: 200,
          headers: {
            "Content-Type": record.mime_type,
            "Cache-Control": "no-store, no-cache, must-revalidate, private",
            "X-Content-Type-Options": "nosniff",
          },
        });
      } catch (e) {
        return json({ ok: false, error: "復号処理に失敗しました" }, 500);
      }
    }

    // 追加：eKYC審査完了（承認 or 差し戻し -> R2から即削除 -> D1更新）
    const reviewMatch = url.pathname.match(/^\/api\/ekyc\/([^/]+)\/review$/);
    if (request.method === "POST" && reviewMatch) {
      try {
        const verificationId = reviewMatch[1];
        const b = await request.json();
        const decision = b.decision;
        const reviewerId = s(b.reviewerId, 100) || "admin";
        const rejectReason = s(b.rejectReason, 300) || "不備あり";

        if (decision !== "approved" && decision !== "rejected") {
          return json({ ok: false, error: "decision は approved または rejected を指定してください" }, 400);
        }

        const record = await env.DB.prepare(
          `SELECT id, user_id, r2_key, status FROM ekyc_verifications WHERE id = ?`
        )
          .bind(verificationId)
          .first();

        if (!record) {
          return json({ ok: false, error: "審査レコードが見つかりません" }, 404);
        }

        // ★ R2から対象ファイルを即削除
        const bucket = env.EKYC_BUCKET || env.IMAGES_BUCKET;
        if (record.r2_key) {
          await bucket.delete(record.r2_key);
        }

        const nowIso = new Date().toISOString();

        await env.DB.batch([
          env.DB.prepare(
            `UPDATE ekyc_verifications
             SET status = ?,
                 reject_reason = ?,
                 reviewed_by = ?,
                 reviewed_at = ?,
                 deleted_at = ?,
                 r2_key = NULL,
                 iv_b64 = NULL,
                 updated_at = ?
             WHERE id = ?`
          ).bind(
            decision,
            decision === "rejected" ? rejectReason : null,
            reviewerId,
            nowIso,
            nowIso,
            nowIso,
            verificationId
          ),
          env.DB.prepare(
            `UPDATE users SET kyc_status = ?, updated_at = ? WHERE id = ?`
          ).bind(decision, nowIso, record.user_id),
        ]);

        return json({
          ok: true,
          verificationId,
          status: decision,
          r2Deleted: true,
          deletedAt: nowIso,
        });
      } catch (e) {
        return json({ ok: false, error: "審査処理に失敗しました" }, 500);
      }
    }

    return env.ASSETS.fetch(request);
  },
};

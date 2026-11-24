const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json; charset=UTF-8" },
  });

const s = (v, n = 300) => String(v || "").trim().slice(0, n);

const FEE_RATE_BPS = {
  attended: 2000,
  unattended_card: 2500,
};

function makeId(prefix) {
  return `${prefix}_${crypto.randomUUID()}`;
}

function makeBookingCode() {
  const ymd = new Date().toISOString().slice(0, 10).replace(/-/g, "");
  const rand = Math.floor(1000 + Math.random() * 9000);
  return `SB-${ymd}-${rand}`;
}

function makeReceiptNo() {
  const ymd = new Date().toISOString().slice(0, 10).replace(/-/g, "");
  const rand = Math.floor(1000 + Math.random() * 9000);
  return `RCP-${ymd}-${rand}`;
}

function calcFeeJpy(amountJpy, rateBps) {
  return Math.floor((amountJpy * rateBps) / 10000);
}

function resolveReceiptPeriod(billingCycle, anchorDateStr) {
  const m = String(anchorDateStr || "").match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (!m) return null;
  const year = Number(m[1]);
  const month = Number(m[2]);
  const day = Number(m[3]);
  const check = new Date(Date.UTC(year, month - 1, day));
  if (
    check.getUTCFullYear() !== year ||
    check.getUTCMonth() !== month - 1 ||
    check.getUTCDate() !== day
  ) {
    return null;
  }
  const mm = String(month).padStart(2, "0");
  const lastDay = new Date(Date.UTC(year, month, 0)).getUTCDate();
  const ddLast = String(lastDay).padStart(2, "0");

  if (billingCycle === "per_booking") {
    const dd = String(day).padStart(2, "0");
    const d = `${year}-${mm}-${dd}`;
    return { periodStartDate: d, periodEndDate: d };
  }
  if (billingCycle === "half_month") {
    if (day <= 15) {
      return { periodStartDate: `${year}-${mm}-01`, periodEndDate: `${year}-${mm}-15` };
    }
    return { periodStartDate: `${year}-${mm}-16`, periodEndDate: `${year}-${mm}-${ddLast}` };
  }
  if (billingCycle === "monthly") {
    return { periodStartDate: `${year}-${mm}-01`, periodEndDate: `${year}-${mm}-${ddLast}` };
  }
  return null;
}

function formatReceiptItemRow(row) {
  const baseAmount = Number(row.amount_jpy || 0);
  const code = row.booking_code || row.booking_id || "";
  if (row.tx_type === "prepay_fee") {
    return { signedAmountJpy: Math.abs(baseAmount), description: `予約先払い手数料（${code}）` };
  }
  if (row.tx_type === "penalty_capture") {
    return { signedAmountJpy: Math.abs(baseAmount), description: `キャンセル料・ペナルティ（${code}）` };
  }
  if (row.tx_type === "refund") {
    return { signedAmountJpy: -Math.abs(baseAmount), description: `返金調整（${code}）` };
  }
  return {
    signedAmountJpy: baseAmount,
    description: `利用明細（${row.tx_type || "payment"} / ${code}）`,
  };
}

function safeJsonArray(str, fallback = []) {
  try {
    const parsed = JSON.parse(str || "[]");
    return Array.isArray(parsed) ? parsed : fallback;
  } catch {
    return fallback;
  }
}

// ---- 管理者認証（パスワードと秘密鍵はCloudflareの変数のみ） ----
function getAdminSecret(env) {
  return String(env.ADMIN_TOKEN_SECRET || "");
}

function verifyAdminPassword(password, env) {
  const input = String(password || "");
  const expected = String(env.ADMIN_PASSWORD || "");
  if (!expected || !input) return false;
  if (input.length !== expected.length) return false;
  let diff = 0;
  for (let i = 0; i < input.length; i++) {
    diff |= input.charCodeAt(i) ^ expected.charCodeAt(i);
  }
  return diff === 0;
}
async function hmacKey(secret, usage) {
  return crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    [usage]
  );
}

async function createAdminToken(env, role = "admin", extra = {}) {
  const secret = getAdminSecret(env);
  if (!secret) throw new Error("ADMIN_TOKEN_SECRET が未設定です");
  const now = Date.now();
  const payload = btoa(
  JSON.stringify({
    ...extra,
    role,
    exp: now + ((role === "owner") ? 30 : 1) * 24 * 60 * 60 * 1000,
  })
);

 
  const key = await hmacKey(secret, "sign");
  const sigBuf = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payload));
  const sigHex = Array.from(new Uint8Array(sigBuf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return `${payload}.${sigHex}`;
}

async function verifyAdminToken(request, env) {
  try {
    const secret = getAdminSecret(env);
    if (!secret) return false;
    const auth = request.headers.get("Authorization") || "";
    const match = auth.match(/^Bearer\s+(.+)$/i);
    if (!match) return false;
    const parts = match[1].trim().split(".");
    if (parts.length !== 2) return false;
    const [payload, sigHex] = parts;

    const key = await hmacKey(secret, "verify");
    const sigBytes = new Uint8Array(
      (sigHex.match(/.{1,2}/g) || []).map((h) => parseInt(h, 16))
    );
    const valid = await crypto.subtle.verify(
      "HMAC",
      key,
      sigBytes,
      new TextEncoder().encode(payload)
    );
    if (!valid) return false;

        const data = JSON.parse(atob(payload));
    const isValidRole = data?.role === "admin" || data?.role === "owner";
    return isValidRole && Number(data.exp) > Date.now();
  } catch {
    return false;
  }
}

async function sendMail(env, to, subject, text) {
  const r = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${env.RESEND_API_KEY}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({
      from: "SalonBase <noreply@weblavo-tokyo.com>",
      to: [to],
      subject,
      text,
    }),
  });
  if (!r.ok) console.log("resend error", r.status, await r.text());
  return r.ok;
}// パスワードをソルト付きSHA-256でハッシュ化するヘルパー
async function hashPassword(password, saltHex = null) {
  const saltBytes = saltHex
    ? Uint8Array.from(saltHex.match(/.{1,2}/g).map((b) => parseInt(b, 16)))
    : crypto.getRandomValues(new Uint8Array(16));

  const resolvedSaltHex = Array.from(saltBytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  const enc = new TextEncoder();
  const data = enc.encode(`${resolvedSaltHex}:${password}`);
  const digest = await crypto.subtle.digest("SHA-256", data);
  const hashHex = Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  return { saltHex: resolvedSaltHex, hashHex };
}

// 振り分け番号を生成するヘルパー（例: SB-2026-4821）
function generateOwnerCode() {
  const year = new Date().getFullYear();
  const rand = Math.floor(1000 + Math.random() * 9000);
  return `SB-${year}-${rand}`;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

        // ---- ログイン ----
    if (path === "/api/auth/login" && method === "POST") {
      try {
        const body = await request.json().catch(() => ({}));
        if (!verifyAdminPassword(body.password, env)) {
          return json({ ok: false, error: "パスワードが正しくありません" }, 401);
        }
        const token = await createAdminToken(env);
        return json({ ok: true, token });
      } catch (err) {
        return json({ ok: false, error: "ログイン処理に失敗しました" }, 500);
      }
    }

    // ---- 画像アップロード ----
    if (path === "/api/upload" && method === "POST") {
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
        // ---- AI文章生成 ----
    if (path === "/api/ai/generate-copy" && method === "POST") {
      try {
        if (!env.AI) {
          return json({ ok: false, error: "Workers AI (env.AI) が設定されていません" }, 500);
        }
        const body = await request.json().catch(() => ({}));
        const target = body.target === "rules" ? "rules" : "description";
        const salon = body.salon || {};

        const prompt =
          target === "rules"
            ? `レンタルサロンの「入室方法・ご利用ルール」を、箇条書き5〜7項目の日本語で作成してください。
サロン名: ${salon.name || ""}
エリア: ${salon.area || ""}
設備: ${salon.amenities || ""}
オーナーのメモ: ${salon.rules || ""}`
            : `レンタルサロンの「お部屋・空間の紹介文」を、上品で信頼感のある日本語で150〜250文字で作成してください。
サロン名: ${salon.name || ""}
エリア・最寄駅: ${salon.area || ""} ${salon.station || ""}
1時間料金: ${salon.price || ""}円
ジャンル: ${salon.genre || ""}
設備: ${salon.amenities || ""}
オーナーのメモ: ${salon.description || ""}`;

        const systemPrompt = `あなたはレンタルサロンの掲載文を書く日本語のライターです。
- オーナーのメモがある場合は、その意味と事実を変えずに、読みやすく上品な文章に整えてください。
- 入力にない設備・条件・事実を勝手に付け足さないでください。誇張もしないでください。
- 前置きや解説は書かず、本文のみを出力してください。`;

        const result = await env.AI.run("@cf/meta/llama-3.3-70b-instruct-fp8-fast", {
          messages: [
            { role: "system", content: systemPrompt },
            { role: "user", content: prompt },
          ],
          max_tokens: 500,
        });

        const text = String(
          result?.response ??
            result?.output_text ??
            result?.result?.response ??
            result?.choices?.[0]?.message?.content ??
            ""
        ).trim();

        if (!text) {
          console.log("ai raw", JSON.stringify(result));
          return json({ ok: false, error: "文章を生成できませんでした。" }, 500);
        }
        return json({ ok: true, text });
      } catch (err) {
        console.log("ai error", String(err));
        return json(
          { ok: false, error: `AI生成エラー: ${err?.message || String(err)}` },
          500
        );
      }
    }

    // ---- 画像配信 ----
    if (path.startsWith("/api/images/") && method === "GET") {
      try {
        const key = decodeURIComponent(path.replace(/^\/api\/images\//, ""));
        if (!key || key.includes("..")) {
          return json({ ok: false, error: "不正なキーです" }, 400);
        }
        const obj = await env.IMAGES_BUCKET.get(key);
        if (!obj) return json({ ok: false, error: "画像が見つかりません" }, 404);
        const headers = new Headers();
        if (obj.httpMetadata?.contentType) {
          headers.set("Content-Type", obj.httpMetadata.contentType);
        }
        headers.set("Cache-Control", "public, max-age=3600");
        return new Response(obj.body, { status: 200, headers });
      } catch {
        return json({ ok: false, error: "画像取得に失敗しました" }, 500);
      }
    }

    // ---- サロン一覧 ----
    if (path === "/api/salons" && method === "GET") {
      try {
        const rows = await env.DB.prepare(
          `SELECT * FROM published_salons ORDER BY id DESC`
        ).all();
                const photoRows = await env.DB.prepare(
          `SELECT salon_id, image_key FROM salon_photos ORDER BY salon_id, sort_order ASC`
        ).all();
        const photoMap = {};
        for (const p of photoRows.results || []) {
          (photoMap[p.salon_id] ||= []).push(`/api/images/${encodeURIComponent(p.image_key)}`);
        }

        const salons = (rows.results || []).map((r) => ({
          id: `db_${r.id}`,
          name: r.name,
          area: r.area,
          station: r.station,
          pricePerHour: Number(r.price_per_hour || 1500),
          rating: Number(r.rating || 4.9),
          reviewCount: Number(r.review_count || 1),
          availabilityBadge: r.availability_badge || "本日空きあり",
          genres: safeJsonArray(r.genres_json, ["エステ・リラク"]),
          equipment: safeJsonArray(r.equipment_json, ["完全個室"]),
          image:
            r.image_url ||
            (r.image_key ? `/api/images/${encodeURIComponent(r.image_key)}` : ""),
          image_key: r.image_key || "",
                    images: photoMap[r.id] || (r.image_key ? [`/api/images/${encodeURIComponent(r.image_key)}`] : []),
          description: r.description || "",
          freeAmenities: safeJsonArray(r.free_amenities_json, []),
          entryRules: r.entry_rules || "",
          bookedHours: safeJsonArray(r.booked_hours_json, []),
        }));
        return json({ ok: true, salons });
      } catch (e) {
        return json({ ok: false, error: "サロン一覧の取得に失敗しました" }, 500);
      }
    }

    // ---- サロン登録（ログイン必須） ----
    if (path === "/api/salons" && method === "POST") {
      try {
        if (!(await verifyAdminToken(request, env))) {
          return json({ ok: false, error: "認証が必要です。再ログインしてください。" }, 401);
        }
        const b = await request.json();
        const name = s(b.name, 120);
        const area = s(b.area, 80);
        const station = s(b.station, 120);
        const pricePerHour = Number(b.pricePerHour);
        if (!name || !area || !station || !Number.isFinite(pricePerHour) || pricePerHour <= 0) {
          return json({ ok: false, error: "サロン名・エリア・最寄り駅・1時間料金は必須です" }, 400);
        }
        const genres =
          Array.isArray(b.genres) && b.genres.length
            ? b.genres.map((x) => s(x, 50))
            : ["エステ・リラク"];
        const equipment = Array.isArray(b.equipment) ? b.equipment.map((x) => s(x, 50)) : [];
        const freeAmenities =
          Array.isArray(b.freeAmenities) && b.freeAmenities.length
            ? b.freeAmenities.map((x) => s(x, 120))
            : ["施術スペース設備完備"];
        const bookedHours = Array.isArray(b.bookedHours)
          ? b.bookedHours.map((x) => s(x, 20))
          : [];
                const imageKeys = Array.isArray(b.image_keys)
          ? b.image_keys.map((x) => s(x, 250)).filter(Boolean).slice(0, 20)
          : [];
        const imageKey = s(b.image_key, 250) || imageKeys[0] || "";
        const rawImage = s(b.image, 500);
        const imageUrl =
          rawImage || (imageKey ? `/api/images/${encodeURIComponent(imageKey)}` : "");
        const nowIso = new Date().toISOString();

        const ins = await env.DB.prepare(
          `INSERT INTO published_salons (
            name, area, station, price_per_hour, rating, review_count,
            availability_badge, genres_json, equipment_json, image_url, image_key,
            description, free_amenities_json, entry_rules, booked_hours_json,
            created_at, updated_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        )
          .bind(
            name,
            area,
            station,
            Math.round(pricePerHour),
            Number(b.rating) || 4.9,
            Number(b.reviewCount) || 1,
            s(b.availabilityBadge, 40) || "本日空きあり",
            JSON.stringify(genres),
            JSON.stringify(equipment),
            imageUrl,
            imageKey,
            s(b.description, 1000) || "プライベートサロン空間です。",
            JSON.stringify(freeAmenities),
            s(b.entryRules, 1000) || "ご予約時間に合わせてご入室・ご退室ください。",
            JSON.stringify(bookedHours),
            nowIso,
            nowIso
          )
          .run();
        const newId = ins.meta?.last_row_id;
                try {
          const rawTok = (request.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "").split(".")[0];
          const tokData = JSON.parse(atob(rawTok));
          if (tokData.owner_id) {
            const ow = await env.DB.prepare("SELECT email FROM owner_entries WHERE id = ?").bind(tokData.owner_id).first();
            if (ow?.email) {
              await env.DB.prepare("UPDATE published_salons SET owner_email = ? WHERE id = ?").bind(ow.email, newId).run();
            }
          }
        } catch (e) {
          console.log("owner email save skipped", String(e));
        }
        for (let i = 0; i < imageKeys.length; i++) {
          await env.DB.prepare(
            `INSERT INTO salon_photos (salon_id, image_key, sort_order, created_at) VALUES (?, ?, ?, ?)`
          ).bind(newId, imageKeys[i], i, nowIso).run();
        }

        return json({ ok: true, id: ins.meta?.last_row_id, imageUrl }, 201);
      } catch (e) {
        return json({ ok: false, error: "サロン情報の保存に失敗しました" }, 500);
      }
    }

    // ---- 掲載エントリー＋メール通知 ----
    if (path === "/api/entry" && method === "POST") {
  try {
    const b = await request.json();
    const salon = s(b.salon_name, 100);
    const person = s(b.person_name, 100);
    const email = s(b.email, 200);
    const phone = s(b.phone, 50);
    const rawPassword = String(b.password || "");

    if (!salon || !person || !email || !phone) {
      return json({ ok: false, error: "必須項目が未入力です" }, 400);
    }
    if (rawPassword.length < 6) {
      return json({ ok: false, error: "ログインパスワードは6文字以上で設定してください" }, 400);
    }

    const ownerCode = generateOwnerCode();
    const { saltHex, hashHex } = await hashPassword(rawPassword);
    const createdAt = new Date().toISOString();

    await env.DB.prepare(
      `INSERT INTO owner_entries
        (created_at, salon_name, area, space_type, person_name, email, phone, image_key, owner_code, password_hash, password_salt)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
      .bind(
        createdAt,
        salon,
        s(b.area, 200),
        s(b.space_type, 50),
        person,
        email,
        phone,
        s(b.image_key, 200),
        ownerCode,
        hashHex,
        saltHex
      )
      .run();

    const adminUrl = "https://salon-base.emikurekura.workers.dev/admin";

    // 運営宛て通知メール（パスワードは記載せず、番号と管理画面URLを案内）
    try {
      if (env.RESEND_API_KEY && env.NOTIFY_EMAIL) {
        const adminText = [
          "新しい掲載エントリーが届きました。",
          "",
          `割り当て番号: ${ownerCode}`,
          `サロン名: ${salon}`,
          `担当者: ${person}`,
          `エリア: ${s(b.area, 200)}`,
          `メール: ${email}`,
          `電話: ${phone}`,
          "",
          "▼ 管理画面（SalonBase Owner Console）",
          adminUrl
        ].join("\n");

        await sendMail(env, env.NOTIFY_EMAIL, `【SalonBase】新規エントリー（${ownerCode}）：${salon}`, adminText);
      }
    } catch (mailErr) {
      console.error("Notify mail error:", mailErr);
    }

    // フロント側へ「割り当て番号」と「管理画面URL」を返して誘導しやすくする
    return json({
      ok: true,
      owner_code: ownerCode,
      admin_url: adminUrl
    });
  } catch (err) {
    return json({ ok: false, error: String(err?.message || err) }, 500);
  }
}
if (path === "/api/owner/login" && method === "POST") {
  try {
    const b = await request.json();
    const ownerCode = String(b.owner_code || "").trim().toUpperCase();
    const rawPassword = String(b.password || "");

    if (!ownerCode || !rawPassword) {
      return json({ ok: false, error: "番号とパスワードを入力してください" }, 400);
    }

    const row = await env.DB.prepare(
      "SELECT id, owner_code, salon_name, person_name, password_hash, password_salt FROM owner_entries WHERE owner_code = ? LIMIT 1"
    )
      .bind(ownerCode)
      .first();

    if (!row || !row.password_hash || !row.password_salt) {
      return json({ ok: false, error: "番号またはパスワードが正しくありません" }, 401);
    }

    const { hashHex } = await hashPassword(rawPassword, row.password_salt);
    if (hashHex !== row.password_hash) {
      return json({ ok: false, error: "番号またはパスワードが正しくありません" }, 401);
    }
        const token = await createAdminToken(env, "owner", { owner_id: row.id });
    return json({
      ok: true,
      token,
      owner: {
        id: row.id,
        owner_code: row.owner_code,
        salon_name: row.salon_name,
        person_name: row.person_name
      }
    });

  } catch (err) {
    return json({ ok: false, error: String(err?.message || err) }, 500);
  }
}
    // ---- 無料見学（30分）の予約＋応募者へのメール送信 ----
    if (path === "/api/tour-bookings" && method === "POST") {
      try {
        const b = await request.json().catch(() => ({}));
        const salonName = s(b.salon_name || b.salonName, 150);
        const applicantName = s(b.name || b.applicant_name, 100);
        const email = s(b.email, 200);
        const phone = s(b.phone, 50);
        const tourDate = s(b.tour_date || b.date, 30);
        const tourTime = s(b.tour_time || b.time, 30);
        const note = s(b.note || b.message, 500);

        if (!salonName || !applicantName || !email || !tourDate || !tourTime) {
          return json(
            { ok: false, error: "サロン名・お名前・メールアドレス・希望日・希望時間を入力してください" },
            400
          );
        }

        const tourId = makeId("tour");
        const createdAt = new Date().toISOString();

        try {
          await env.DB.prepare(
            `INSERT INTO tour_bookings
              (id, salon_name, applicant_name, email, phone, tour_date, tour_time, note, status, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'requested', ?)`
          )
            .bind(
              tourId,
              salonName,
              applicantName,
              email,
              phone,
              tourDate,
              tourTime,
              note,
              createdAt
            )
            .run();
        } catch (dbErr) {
          console.log("tour_bookings insert skipped/error:", String(dbErr));
        }

        if (!env.RESEND_API_KEY) {
          return json({ ok: false, error: "メール送信設定（RESEND_API_KEY）が未設定です" }, 500);
        }

        const guestSubject = `【SalonBase】無料見学（30分）のご予約受付完了：${salonName}`;
        const guestText = [
          `${applicantName} 様`,
          "",
          "SalonBase より、無料見学（30分）のご予約を受け付けました。",
          "",
          "■ ご予約内容",
          `予約番号: ${tourId}`,
          `サロン名: ${salonName}`,
          `ご希望日時: ${tourDate} ${tourTime}`,
          phone ? `電話番号: ${phone}` : "",
          note ? `備考・ご質問: ${note}` : "",
          "",
          "担当者より当日のご案内をお送りいたします。",
          "ご不明点がある場合は、このメールへご返信ください。",
        ]
          .filter(Boolean)
          .join("\n");

        const sentToGuest = await sendMail(env, email, guestSubject, guestText);

        if (env.NOTIFY_EMAIL) {
          const adminText = [
            "新しい無料見学（30分）の予約が入りました。",
            "",
            `予約番号: ${tourId}`,
            `サロン名: ${salonName}`,
            `応募者: ${applicantName}`,
            `メール: ${email}`,
            phone ? `電話: ${phone}` : "",
            `希望日時: ${tourDate} ${tourTime}`,
            note ? `備考: ${note}` : "",
          ]
            .filter(Boolean)
            .join("\n");

          await sendMail(
            env,
            env.NOTIFY_EMAIL,
            `【SalonBase】無料見学予約：${salonName}（${tourDate} ${tourTime}）`,
            adminText
          );
        }

        if (!sentToGuest) {
          return json({ ok: false, error: "応募者へのメール送信に失敗しました" }, 500);
        }

        return json({ ok: true, id: tourId }, 201);
      } catch (err) {
        return json({ ok: false, error: err?.message || "見学予約の処理に失敗しました" }, 500);
      }
    }
          // ---- 自分のサロン一覧（オーナー用） ----
    if (path === "/api/my-salons" && method === "GET") {
      if (!(await verifyAdminToken(request, env))) {
        return json({ ok: false, error: "認証が必要です" }, 401);
      }
      try {
        const rawTok = (request.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "").split(".")[0];
        const tok = JSON.parse(atob(rawTok));
        let rows;
        if (tok.role === "admin") {
          rows = await env.DB.prepare("SELECT id, name FROM published_salons ORDER BY id DESC LIMIT 100").all();
        } else {
          const ow = await env.DB.prepare("SELECT email FROM owner_entries WHERE id = ?").bind(tok.owner_id).first();
          rows = await env.DB.prepare("SELECT id, name FROM published_salons WHERE owner_email = ? ORDER BY id DESC").bind(ow?.email || "").all();
        }
        return json({ ok: true, salons: rows.results || [] });
      } catch (e) {
        return json({ ok: false, error: "取得に失敗しました" }, 500);
      }
    }

    // ---- 日付ごとの休み：取得（公開） ----
    if (path === "/api/closures" && method === "GET") {
      const u = new URL(request.url);
      const sid = parseInt(String(u.searchParams.get("salon_id") || "").replace(/^db_/, ""), 10);
      const date = u.searchParams.get("date");
      if (!sid) return json({ ok: false, error: "salon_id が必要です" }, 400);
      try {
        if (date) {
          const r = await env.DB.prepare("SELECT hours FROM salon_closures WHERE salon_id = ? AND date = ?").bind(sid, date).first();
          return json({ ok: true, hours: r ? JSON.parse(r.hours || "[]") : [] });
        }
        const today = new Date(Date.now() + 9 * 3600 * 1000).toISOString().slice(0, 10);
        const rows = await env.DB.prepare("SELECT date, hours FROM salon_closures WHERE salon_id = ? AND date >= ? ORDER BY date").bind(sid, today).all();
        return json({ ok: true, closures: (rows.results || []).map((x) => ({ date: x.date, hours: JSON.parse(x.hours || "[]") })) });
      } catch (e) {
        return json({ ok: false, error: "取得に失敗しました" }, 500);
      }
    }

    // ---- 日付ごとの休み：保存（ログイン必須） ----
    if (path === "/api/closures" && method === "POST") {
      if (!(await verifyAdminToken(request, env))) {
        return json({ ok: false, error: "認証が必要です" }, 401);
      }
      try {
        const body = await request.json();
        const sid = parseInt(body.salon_id, 10);
        const date = String(body.date || "");
        const hours = Array.isArray(body.hours) ? body.hours.filter((h) => /^\d{2}:\d{2}$/.test(h)) : [];
        if (!sid || !/^\d{4}-\d{2}-\d{2}$/.test(date)) {
          return json({ ok: false, error: "サロンと日付を選んでください" }, 400);
        }
        const rawTok = (request.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "").split(".")[0];
        const tok = JSON.parse(atob(rawTok));
        if (tok.role !== "admin") {
          const ow = await env.DB.prepare("SELECT email FROM owner_entries WHERE id = ?").bind(tok.owner_id).first();
          const sal = await env.DB.prepare("SELECT owner_email FROM published_salons WHERE id = ?").bind(sid).first();
          if (!ow?.email || !sal || sal.owner_email !== ow.email) {
            return json({ ok: false, error: "このサロンは編集できません" }, 403);
          }
        }
        if (hours.length === 0) {
          await env.DB.prepare("DELETE FROM salon_closures WHERE salon_id = ? AND date = ?").bind(sid, date).run();
        } else {
          await env.DB.prepare("INSERT OR REPLACE INTO salon_closures (salon_id, date, hours) VALUES (?, ?, ?)").bind(sid, date, JSON.stringify(hours)).run();
        }
        return json({ ok: true });
      } catch (e) {
        return json({ ok: false, error: "保存に失敗しました" }, 500);
      }
    }
    // ---- 管理画面アプリ化（マニフェストとアイコン） ----
    if (path === "/admin.webmanifest" && method === "GET") {
      return new Response(JSON.stringify({
        name: "SalonBase オーナー管理",
        short_name: "SalonBase",
        start_url: "/admin",
        scope: "/",
        display: "standalone",
        background_color: "#FAF7F2",
        theme_color: "#C4826E",
        icons: [{ src: "/admin-icon.png", sizes: "256x256", type: "image/png", purpose: "any" }]
      }), { headers: { "content-type": "application/manifest+json; charset=UTF-8" } });
    }
    if (path === "/admin-icon.png" && method === "GET") {
      const bin = Uint8Array.from(atob("iVBORw0KGgoAAAANSUhEUgAAAQAAAAEABAMAAACuXLVVAAAAElBMVEX8+fjFgm7Egm/Egm7Egm3BfGfOeeMGAAAGXUlEQVR42u2dz28aRxTH3wyOZasClvpQqWpiwgZFVYVxvOm5lvIHtE3+TlttD721qnroxeVXUJVGLmSxq6hS5OwCapIqZqcHY4xhdnd+Lony9sSODe+z3/fmx5sZBuLBai8KCIAACIAACIAACIAACIAACIAACIAACIAACIAACIAACIAAHzrAmt7bAwAorRAg8ACgUVoZQOgd+UAf9ciKYiC4d+QDRAdbwWoAmPu7DwAQ/bQXqn9K7lPlt45f+FOSP/eHK1CA1fzLl1E3XAHAuHn1ulfP3gXsk9bczds3G5krUJi/GWTvgvF383dv61kDsNr1e+UwVAUYNa/f97YzBiD+9fvIyRZg0QPqPlAEGL5cLHlWzBSA+oslUTlLAFZcBhiGWSpwa7noJEsFlkNAOQiooRBQDgI1gCIPYJgdALvFKz0Js1Mg4hX62SkwbvNKJ/XsFPCFZbEDUOAXD7ICYDFd7yjMSoFIwjE2AEZtfvlk205uuJQBx6aCznDxfcTRBmAjD4D1w1K61tc8ExDXATgbOLoA451GHypbe80rgthYY3P23UKrD5VcfaCZmLC7hwFA8PyN19+cVYJnMf98PktPAu+P3wKA4OX5q029ILxMwPoH3iwJj1WVXE1cHPWno+V7oRYA++LS39HBLAmP0hpI5h7N3vaDXjWcy3+iw/oFAYt/puk/jI994ZyJio++o+5FPR/HNjjT7mhU88XH61Qi/zk+DRObgWl0sJ1DiZyJyuQ/vd0wscmNAABYrimTMyUCsJsLBr4X6PLHHy0APg7VFViEP++GS1QLtljtl7jKqQCwVOF69RASJCXAxk25TpLKdXtRN2X0P6z5cp1kIgBHvOOPw4Shl89uH6Y7UsIFHPV+3k3sWv6SHStKD0iibjv+j5Oab39E1Ev6YzODIVkkPV43PSb0FeHkAZKaHJkrsSnERat3GoCMzNjYdlQVGJoBKGIMIIA6QNm+CXRBYnpemJgwQQbqeYGZGAjf4xgwglfWMBGaAGDqAKRrAqDmmMsN1WqBjpfL1lsaquE+wUtnhqSwq28/N7AnkIFamGYhtF0L0+aITvUBdhwtjcu2u1sKtquB3lStfjVIqQS6CmlXglQDoeVKkAagXw1SKkG6xGXLY861hJUqEFp1Stttc+nEkgwAC92p4bNCW0+B0fSMCdbkPwsXIHDdRuQDAC3Dnp4C+73LT/JYkycC8XhbJRv9q0eI9GqhP3tZ8ZqOEADLvfDtDIC/bTsiUTrO27EPUacusm7I7v5oKwd4ef56I12BcROsXZytn1Rgk5RBJyxvt1pW4DObidiv6QqM2jYBlldPqFwaoX056S7wbdqPUl1gaoYcRGfOqZV0UCJRxEkqamVOQmKISC3kQlJDxHcwBsrZmqNW5iQk8gxqY05CJlGj2VbMcro5M1NzIDxlRyHLKKQiRXmLQZDrqDFZDAGONZtBUBPKC5i1IOCtHHAACnu2ANyBEIA9H/DmzXkRl//Gjv0bHdEBycgOwLboiIicWglDyp0u4iqQtxKGbkd4TEi6FiSg/KUbfrNnQwK+ADEAFiSIESCu4TcvQYwAcQDGJYgTILbrMy1BnACxAIYliBUgvvPPV00CPOxI54ak/9Cc/WrfkU9Oi+acQGtDheyYmItDt+OopOeku2/G/lrS+nnSCDT/rxEn0K87qrvpJvdNADxoK++mIy0DNaF6prOBQT8M1mpaGxi0wyA5AASW7Sb3tQhocgAI5GGkpdUauGeO7jSd81gjEKs3if48YaGrTFCtDQxMVJK8KkG11nFMzJSqEgjZFzqFg6yf7r+WnUGld4Tsix0DQtZPvFd8ArodU/7oxlPH3Gk8pND4kva5D7Dr84orXkNw2VvwIBSy2Xd3n/Aaur/XORJU7zVLG4ZPYtl8/oITCHf+Wf/8Ccf9rZL5o2A210+8N8XrCPSr/8hpYaHs9oMbT0s2TmQixYbr0GjO55W9lgP5rfnooGWPNUoS6z5E6jcsWOg6vXBqr7K13SzB5fdbL4rIXtxGBTMAAAFslQGgAbnd2XeBA1JxJm3wACBqyR7SRaR/xYOFAFCByJ8zFQAtQ19pywlR+xkRFi4+aKC43UXxWDCyJHQJv1+AAAiAAAiAAAiAAAiAAAiAAAiAAAiAAAiAAAiAAAiAAAiAAAiAAAjwvgL8D1KSwEcXFX5+AAAAAElFTkSuQmCC"), (c) => c.charCodeAt(0));
      return new Response(bin, { headers: { "content-type": "image/png", "cache-control": "public, max-age=86400" } });
    }
    // ================= Stripe 決済（Connect v2） =================
    const STRIPE_V2_VERSION = "2026-11-18.endive";

    const stripeFetch = async (httpMethod, endpoint, params) => {
      if (!env.STRIPE_SECRET_KEY) throw new Error("STRIPE_SECRET_KEY が未設定です");
      const r = await fetch("https://api.stripe.com/v1" + endpoint, {
        method: httpMethod,
        headers: {
          Authorization: `Bearer ${env.STRIPE_SECRET_KEY}`,
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: params ? new URLSearchParams(params).toString() : undefined,
      });
      const j = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(j?.error?.message || "Stripe エラー");
      return j;
    };

    const stripeV2Fetch = async (httpMethod, endpoint, bodyObj) => {
      if (!env.STRIPE_SECRET_KEY) throw new Error("STRIPE_SECRET_KEY が未設定です");
      const r = await fetch("https://api.stripe.com" + endpoint, {
        method: httpMethod,
        headers: {
          Authorization: `Bearer ${env.STRIPE_SECRET_KEY}`,
          "Stripe-Version": STRIPE_V2_VERSION,
          "Content-Type": "application/json",
        },
        body: bodyObj ? JSON.stringify(bodyObj) : undefined,
      });
      const j = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(j?.error?.message || "Stripe v2 エラー");
      return j;
    };

    const tokenOf = () => {
      const rawTok = (request.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "").split(".")[0];
      return JSON.parse(atob(rawTok));
    };

    // ---- オーナーの受け取り口座の登録（Stripe v2 画面へ移動） ----
    if (path === "/api/stripe/connect" && method === "POST") {
      if (!(await verifyAdminToken(request, env))) return json({ ok: false, error: "認証が必要です" }, 401);
      try {
        const tok = tokenOf();
        if (tok.role !== "owner" || !tok.owner_id) return json({ ok: false, error: "オーナーでログインしてください" }, 403);
        const ow = await env.DB.prepare("SELECT id, email, stripe_account_id FROM owner_entries WHERE id = ?").bind(tok.owner_id).first();
        if (!ow) return json({ ok: false, error: "オーナーが見つかりません" }, 404);

        let acct = ow.stripe_account_id;
        if (!acct) {
          const created = await stripeV2Fetch("POST", "/v2/core/accounts", {
            contact_email: ow.email || "",
            identity: { country: "JP" },
            dashboard: "express",
            configuration: {
              merchant: {
                capabilities: {
                  card_payments: { requested: true },
                },
              },
              recipient: {
                capabilities: {
                  stripe_balance: {
                    payouts: { requested: true },
                  },
                },
              },
            },
          });
          acct = created.id;
          await env.DB.prepare("UPDATE owner_entries SET stripe_account_id = ? WHERE id = ?").bind(acct, ow.id).run();
        }

        const link = await stripeV2Fetch("POST", "/v2/core/account_links", {
          account: acct,
          use_case: {
            type: "account_onboarding",
            account_onboarding: {
              configurations: ["merchant", "recipient"],
              refresh_url: `${url.origin}/admin?stripe=refresh`,
              return_url: `${url.origin}/admin?stripe=return`,
            },
          },
        });
        return json({ ok: true, url: link.url });
      } catch (e) {
        return json({ ok: false, error: String(e?.message || e) }, 500);
      }
    }

    // ---- 受け取り設定の状況 ----
    if (path === "/api/stripe/status" && method === "GET") {
      if (!(await verifyAdminToken(request, env))) return json({ ok: false, error: "認証が必要です" }, 401);
      try {
        const tok = tokenOf();
        if (tok.role !== "owner" || !tok.owner_id) return json({ ok: true, connected: false, charges_enabled: false });
        const ow = await env.DB.prepare("SELECT stripe_account_id FROM owner_entries WHERE id = ?").bind(tok.owner_id).first();
        if (!ow?.stripe_account_id) return json({ ok: true, connected: false, charges_enabled: false });
        const a = await stripeV2Fetch("GET", `/v2/core/accounts/${ow.stripe_account_id}?include[]=configuration.merchant&include[]=requirements`);
        const chargesEnabled = !!a?.configuration?.merchant?.capabilities?.card_payments?.status === "active" || !!a?.charges_enabled;
        return json({
          ok: true,
          connected: true,
          charges_enabled: chargesEnabled,
          details_submitted: !a?.requirements?.summary?.minimum_deadline?.current_deadline,
        });
      } catch (e) {
        return json({ ok: false, error: String(e?.message || e) }, 500);
      }
    }

    // ---- オーナーの受け取り口座の登録（Stripeの画面へ移動） ----
    if (path === "/api/stripe/connect" && method === "POST") {
      if (!(await verifyAdminToken(request, env))) return json({ ok: false, error: "認証が必要です" }, 401);
      try {
        const tok = tokenOf();
        if (tok.role !== "owner" || !tok.owner_id) return json({ ok: false, error: "オーナーでログインしてください" }, 403);
        const ow = await env.DB.prepare("SELECT id, email, stripe_account_id FROM owner_entries WHERE id = ?").bind(tok.owner_id).first();
        if (!ow) return json({ ok: false, error: "オーナーが見つかりません" }, 404);
        let acct = ow.stripe_account_id;
        if (!acct) {
          const created = await stripeFetch("POST", "/accounts", {
            "controller[stripe_dashboard][type]": "express",
            "controller[fees][payer]": "application",
            "controller[losses][payments]": "application",
            country: "JP",
            email: ow.email || "",
            "capabilities[card_payments][requested]": "true",
            "capabilities[transfers][requested]": "true",
          });
          acct = created.id;
          await env.DB.prepare("UPDATE owner_entries SET stripe_account_id = ? WHERE id = ?").bind(acct, ow.id).run();
        }
        const link = await stripeFetch("POST", "/account_links", {
          account: acct,
          refresh_url: `${url.origin}/admin?stripe=refresh`,
          return_url: `${url.origin}/admin?stripe=return`,
          type: "account_onboarding",
        });
        return json({ ok: true, url: link.url });
      } catch (e) {
        return json({ ok: false, error: String(e?.message || e) }, 500);
      }
    }

    // ---- 受け取り設定の状況 ----
    if (path === "/api/stripe/status" && method === "GET") {
      if (!(await verifyAdminToken(request, env))) return json({ ok: false, error: "認証が必要です" }, 401);
      try {
        const tok = tokenOf();
        if (tok.role !== "owner" || !tok.owner_id) return json({ ok: true, connected: false, charges_enabled: false });
        const ow = await env.DB.prepare("SELECT stripe_account_id FROM owner_entries WHERE id = ?").bind(tok.owner_id).first();
        if (!ow?.stripe_account_id) return json({ ok: true, connected: false, charges_enabled: false });
        const a = await stripeFetch("GET", "/accounts/" + ow.stripe_account_id);
        return json({
          ok: true,
          connected: true,
          charges_enabled: !!a.charges_enabled,
          details_submitted: !!a.details_submitted,
        });
      } catch (e) {
        return json({ ok: false, error: String(e?.message || e) }, 500);
      }
    }

    // ---- お客様の予約＋カード決済（Stripe Checkout へ） ----
    if (path === "/api/checkout" && method === "POST") {
      try {
        const b = await request.json().catch(() => ({}));
        const m = String(b.salon_id || "").match(/^db_(\d+)$/);
        const date = s(b.date, 10);
        const hours = Array.isArray(b.hours) ? [...new Set(b.hours.map((h) => s(h, 5)))].filter((h) => /^\d{2}:00$/.test(h)).sort() : [];
        const guestName = s(b.guest_name, 100);
        const guestEmail = s(b.guest_email, 200);
        const guestPhone = s(b.guest_phone, 50);
        if (!m || !/^\d{4}-\d{2}-\d{2}$/.test(date) || hours.length === 0 || !guestName) {
          return json({ ok: false, error: "サロン・日付・時間・お名前を確認してください" }, 400);
        }
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(guestEmail)) {
          return json({ ok: false, error: "メールアドレスの形式が正しくありません" }, 400);
        }
        const salonId = Number(m[1]);
        const salon = await env.DB.prepare("SELECT id, name, price_per_hour, owner_email, booked_hours_json FROM published_salons WHERE id = ?").bind(salonId).first();
        if (!salon) return json({ ok: false, error: "サロンが見つかりません" }, 404);

        const fixedClosed = safeJsonArray(salon.booked_hours_json, []);
        const cl = await env.DB.prepare("SELECT hours FROM salon_closures WHERE salon_id = ? AND date = ?").bind(salonId, date).first();
        const dayClosed = cl ? safeJsonArray(cl.hours, []) : [];
        if (hours.some((h) => fixedClosed.includes(h) || dayClosed.includes(h))) {
          return json({ ok: false, error: "選択した時間に、お受けできない枠があります" }, 409);
        }
        const holdSince = new Date(Date.now() - 35 * 60 * 1000).toISOString();
        const taken = await env.DB.prepare(
          "SELECT hours FROM salon_bookings WHERE salon_id = ? AND date = ? AND (status = 'paid' OR (status = 'pending' AND created_at > ?))"
        ).bind(salonId, date, holdSince).all();
        for (const row of taken.results || []) {
          const used = safeJsonArray(row.hours, []);
          if (hours.some((h) => used.includes(h))) {
            return json({ ok: false, error: "選択した時間は、すでに予約されています" }, 409);
          }
        }

        const ow = await env.DB.prepare("SELECT stripe_account_id FROM owner_entries WHERE email = ? AND stripe_account_id IS NOT NULL LIMIT 1").bind(salon.owner_email || "").first();
        if (!ow?.stripe_account_id) {
          return json({ ok: false, error: "このサロンは、現在オンライン決済に対応していません" }, 400);
        }
        const acct = await stripeFetch("GET", "/accounts/" + ow.stripe_account_id);
        if (!acct.charges_enabled) {
          return json({ ok: false, error: "このサロンの受け取り設定が、まだ完了していません" }, 400);
        }

        const total = Number(salon.price_per_hour) * hours.length;
        if (!Number.isFinite(total) || total < 50) return json({ ok: false, error: "金額が正しくありません" }, 400);
        const fee = calcFeeJpy(total, FEE_RATE_BPS.attended);
        const code = makeBookingCode();
        const nowIso = new Date().toISOString();
        const ins = await env.DB.prepare(
          `INSERT INTO salon_bookings (booking_code, salon_id, salon_name, owner_email, date, hours, amount_jpy, fee_jpy, guest_name, guest_email, guest_phone, status, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)`
        ).bind(code, salonId, salon.name, salon.owner_email || "", date, JSON.stringify(hours), total, fee, guestName, guestEmail, guestPhone, nowIso).run();
        const bookingId = ins.meta?.last_row_id;

        const session = await stripeFetch("POST", "/checkout/sessions", {
          mode: "payment",
          "line_items[0][price_data][currency]": "jpy",
          "line_items[0][price_data][product_data][name]": `${salon.name}（${date} ${hours.join("・")}）`,
          "line_items[0][price_data][unit_amount]": String(total),
          "line_items[0][quantity]": "1",
          "payment_intent_data[application_fee_amount]": String(fee),
          "payment_intent_data[transfer_data][destination]": ow.stripe_account_id,
          customer_email: guestEmail,
          "metadata[booking_id]": String(bookingId),
          expires_at: String(Math.floor(Date.now() / 1000) + 31 * 60),
          success_url: `${url.origin}/?paid=${encodeURIComponent(code)}`,
          cancel_url: `${url.origin}/?canceled=1`,
        });
        await env.DB.prepare("UPDATE salon_bookings SET stripe_session_id = ? WHERE id = ?").bind(session.id, bookingId).run();
        return json({ ok: true, url: session.url });
      } catch (e) {
        console.log("checkout error", String(e));
        return json({ ok: false, error: "決済の準備に失敗しました。時間をおいてお試しください" }, 500);
      }
    }

    // ---- Stripe からの支払い完了通知（Webhook） ----
    if (path === "/api/stripe/webhook" && method === "POST") {
      try {
        const raw = await request.text();
        const sigHeader = request.headers.get("Stripe-Signature") || "";
        const parts = Object.fromEntries(sigHeader.split(",").map((kv) => kv.split("=")).filter((a) => a.length === 2));
        const secret = String(env.STRIPE_WEBHOOK_SECRET || "");
        if (!secret || !parts.t || !parts.v1) return json({ ok: false }, 400);
        const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
        const sigBuf = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(`${parts.t}.${raw}`));
        const expected = Array.from(new Uint8Array(sigBuf)).map((x) => x.toString(16).padStart(2, "0")).join("");
        const fresh = Math.abs(Date.now() / 1000 - Number(parts.t)) < 300;
        if (expected !== parts.v1 || !fresh) return json({ ok: false }, 400);

        const event = JSON.parse(raw);
        const obj = event?.data?.object || {};
        const bookingId = Number(obj?.metadata?.booking_id || 0);

        if (event.type === "checkout.session.expired" && bookingId) {
          await env.DB.prepare("UPDATE salon_bookings SET status = 'expired' WHERE id = ? AND status = 'pending'").bind(bookingId).run();
        }
        if (event.type === "checkout.session.completed" && bookingId && obj.payment_status === "paid") {
          const bk = await env.DB.prepare("SELECT * FROM salon_bookings WHERE id = ?").bind(bookingId).first();
          if (bk && bk.status !== "paid") {
            await env.DB.prepare("UPDATE salon_bookings SET status = 'paid' WHERE id = ?").bind(bookingId).run();
            const hrs = safeJsonArray(bk.hours, []).join(" / ");
            const [yy, mm, dd] = String(bk.date).split("-");
            const when = `${yy}年${Number(mm)}月${Number(dd)}日 ${hrs}`;
            const guestText = [
              `${bk.guest_name} 様`, "", "ご予約とお支払いが完了しました。", "",
              `予約番号: ${bk.booking_code}`, `サロン: ${bk.salon_name}`, `ご利用日時: ${when}`,
              `お支払い金額: ¥${Number(bk.amount_jpy).toLocaleString()}`, "", "※ このメールは送信専用です。", "SalonBase",
            ].join("\n");
            const ownerText = [
              "新しい予約（お支払い済み）が入りました。", "",
              `予約番号: ${bk.booking_code}`, `サロン: ${bk.salon_name}`, `ご利用日時: ${when}`,
              `お支払い金額: ¥${Number(bk.amount_jpy).toLocaleString()}`,
              `運営手数料: ¥${Number(bk.fee_jpy).toLocaleString()}`,
              `お受け取り予定額: ¥${(Number(bk.amount_jpy) - Number(bk.fee_jpy)).toLocaleString()}`, "",
              `お客様: ${bk.guest_name} 様`, `メール: ${bk.guest_email}`, bk.guest_phone ? `電話: ${bk.guest_phone}` : "", "", "SalonBase",
            ].filter((x) => x !== "").join("\n");
            await sendMail(env, bk.guest_email, "【SalonBase】ご予約・お支払いが完了しました", guestText);
            const adminEmail = env.NOTIFY_EMAIL || "";
            const toOwner = bk.owner_email || adminEmail;
            if (toOwner) await sendMail(env, toOwner, `【SalonBase】新規予約（支払い済み）：${bk.salon_name}`, ownerText);
            if (adminEmail && adminEmail !== toOwner) await sendMail(env, adminEmail, `【SalonBase】（運営控え）新規予約：${bk.salon_name}`, ownerText);
          }
        }
        return json({ ok: true });
      } catch (e) {
        console.log("webhook error", String(e));
        return json({ ok: false }, 500);
      }
    }


    // ---- 見学リクエスト一覧（ログイン必須） ----
    if (path === "/api/tours" && method === "GET") {
      if (!(await verifyAdminToken(request, env))) {
        return json({ ok: false, error: "認証が必要です" }, 401);
      }
      try {
        const rawTok = (request.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "").split(".")[0];
        const tok = JSON.parse(atob(rawTok));
        let rows;
        if (tok.role === "admin") {
          rows = await env.DB.prepare("SELECT * FROM tour_requests ORDER BY id DESC LIMIT 100").all();
        } else {
          const ow = await env.DB.prepare("SELECT email FROM owner_entries WHERE id = ?").bind(tok.owner_id).first();
          rows = await env.DB.prepare(
            "SELECT * FROM tour_requests WHERE owner_email = ? ORDER BY id DESC LIMIT 100"
          ).bind(ow?.email || "").all();
        }
        return json({ ok: true, tours: rows.results || [] });
      } catch (e) {
        return json({ ok: false, error: "取得に失敗しました" }, 500);
      }
    }

    // ---- 自分のサロン（詳細つき・オーナー用） ----
    if (path === "/api/owner/salons" && method === "GET") {
      if (!(await verifyAdminToken(request, env))) {
        return json({ ok: false, error: "認証が必要です" }, 401);
      }
      try {
        const rawTok = (request.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "").split(".")[0];
        const tok = JSON.parse(atob(rawTok));
        let rows;
        if (tok.role === "admin") {
          rows = await env.DB.prepare("SELECT * FROM published_salons ORDER BY id DESC LIMIT 100").all();
        } else {
          const ow = await env.DB.prepare("SELECT email FROM owner_entries WHERE id = ?").bind(tok.owner_id).first();
          rows = await env.DB.prepare("SELECT * FROM published_salons WHERE owner_email = ? ORDER BY id DESC").bind(ow?.email || "").all();
        }
        const list = rows.results || [];
        const photoRows = await env.DB.prepare(
          "SELECT salon_id, image_key FROM salon_photos ORDER BY salon_id, sort_order ASC"
        ).all();
        const photoMap = {};
        for (const p of photoRows.results || []) {
          (photoMap[p.salon_id] ||= []).push({ key: p.image_key, url: `/api/images/${encodeURIComponent(p.image_key)}` });
        }
        const salons = list.map((r) => ({
          id: r.id,
          name: r.name,
          area: r.area,
          station: r.station,
          price: Number(r.price_per_hour || 0),
          badge: r.availability_badge || "本日空きあり",
          genres: safeJsonArray(r.genres_json, []),
          equipment: safeJsonArray(r.equipment_json, []),
          freeAmenities: safeJsonArray(r.free_amenities_json, []),
          description: r.description || "",
          entryRules: r.entry_rules || "",
          bookedHours: safeJsonArray(r.booked_hours_json, []),
          photos: photoMap[r.id] || (r.image_key ? [{ key: r.image_key, url: `/api/images/${encodeURIComponent(r.image_key)}` }] : []),
        }));
        return json({ ok: true, salons });
      } catch (e) {
        return json({ ok: false, error: "取得に失敗しました" }, 500);
      }
    }

    // ---- サロン内容の変更・削除（ログイン必須） ----
    const salonIdMatch = path.match(/^\/api\/salons\/(\d+)$/);
    if (salonIdMatch && (method === "PUT" || method === "DELETE")) {
      if (!(await verifyAdminToken(request, env))) {
        return json({ ok: false, error: "認証が必要です" }, 401);
      }
      try {
        const sid = Number(salonIdMatch[1]);
        const rawTok = (request.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "").split(".")[0];
        const tok = JSON.parse(atob(rawTok));
        const sal = await env.DB.prepare("SELECT id, owner_email FROM published_salons WHERE id = ?").bind(sid).first();
        if (!sal) return json({ ok: false, error: "サロンが見つかりません" }, 404);
        if (tok.role !== "admin") {
          const ow = await env.DB.prepare("SELECT email FROM owner_entries WHERE id = ?").bind(tok.owner_id).first();
          if (!ow?.email || sal.owner_email !== ow.email) {
            return json({ ok: false, error: "このサロンは編集できません" }, 403);
          }
        }

        if (method === "DELETE") {
          await env.DB.prepare("DELETE FROM salon_photos WHERE salon_id = ?").bind(sid).run();
          await env.DB.prepare("DELETE FROM salon_closures WHERE salon_id = ?").bind(sid).run();
          await env.DB.prepare("DELETE FROM published_salons WHERE id = ?").bind(sid).run();
          return json({ ok: true });
        }

        const b = await request.json();
        const name = s(b.name, 120);
        const area = s(b.area, 80);
        const station = s(b.station, 120) || area;
        const pricePerHour = Number(b.pricePerHour);
        if (!name || !area || !Number.isFinite(pricePerHour) || pricePerHour <= 0) {
          return json({ ok: false, error: "サロン名・エリア・1時間料金は必須です" }, 400);
        }
        const genres = Array.isArray(b.genres) && b.genres.length ? b.genres.map((x) => s(x, 50)) : ["エステ・リラク"];
        const equipment = Array.isArray(b.equipment) ? b.equipment.map((x) => s(x, 50)) : [];
        const freeAmenities = Array.isArray(b.freeAmenities) ? b.freeAmenities.map((x) => s(x, 120)).filter(Boolean) : [];
        const bookedHours = Array.isArray(b.bookedHours) ? b.bookedHours.map((x) => s(x, 20)) : [];
        const nowIso = new Date().toISOString();

        let imageKey = null;
        let imageKeys = null;
        if (Array.isArray(b.image_keys)) {
          imageKeys = b.image_keys.map((x) => s(x, 250)).filter((x) => x.startsWith("owners/")).slice(0, 20);
          imageKey = imageKeys[0] || "";
        }

        await env.DB.prepare(
          `UPDATE published_salons SET
            name = ?, area = ?, station = ?, price_per_hour = ?, availability_badge = ?,
            genres_json = ?, equipment_json = ?, description = ?, free_amenities_json = ?,
            entry_rules = ?, booked_hours_json = ?, updated_at = ?
           WHERE id = ?`
        ).bind(
          name, area, station, Math.round(pricePerHour), s(b.availabilityBadge, 40) || "本日空きあり",
          JSON.stringify(genres), JSON.stringify(equipment), s(b.description, 1000),
          JSON.stringify(freeAmenities), s(b.entryRules, 1000), JSON.stringify(bookedHours),
          nowIso, sid
        ).run();

        if (imageKeys) {
          await env.DB.prepare("DELETE FROM salon_photos WHERE salon_id = ?").bind(sid).run();
          for (let i = 0; i < imageKeys.length; i++) {
            await env.DB.prepare(
              "INSERT INTO salon_photos (salon_id, image_key, sort_order, created_at) VALUES (?, ?, ?, ?)"
            ).bind(sid, imageKeys[i], i, nowIso).run();
          }
          await env.DB.prepare("UPDATE published_salons SET image_key = ?, image_url = ? WHERE id = ?")
            .bind(imageKey, imageKey ? `/api/images/${encodeURIComponent(imageKey)}` : "", sid).run();
        }
        return json({ ok: true });
      } catch (e) {
        return json({ ok: false, error: "保存に失敗しました" }, 500);
      }
    }


    // ---- 無料見学リクエスト（お客様・オーナー双方へメール） ----
    if (path === "/api/tours" && method === "POST") {
      try {
        const b = await request.json().catch(() => ({}));
        const salonIdRaw = s(b.salon_id, 60);
        const salonName = s(b.salon_name, 150);
        const guestName = s(b.name, 80);
        const guestEmail = s(b.email, 200);
        const guestPhone = s(b.phone, 40);
        const date = s(b.date, 10);
        const time = s(b.time, 5);
        const message = s(b.message, 500);

        if (!salonName || !guestName || !guestEmail || !date || !time) {
          return json({ ok: false, error: "必須項目が未入力です" }, 400);
        }
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(guestEmail)) {
          return json({ ok: false, error: "メールアドレスの形式が正しくありません" }, 400);
        }
        if (!/^\d{4}-\d{2}-\d{2}$/.test(date) || !/^\d{2}:\d{2}$/.test(time)) {
          return json({ ok: false, error: "日時の形式が正しくありません" }, 400);
        }
        const closeM = salonIdRaw.match(/^db_(\d+)$/);
        if (closeM) {
          const cl = await env.DB.prepare(
            "SELECT hours FROM salon_closures WHERE salon_id = ? AND date = ?"
          ).bind(Number(closeM[1]), date).first();
          if (cl && safeJsonArray(cl.hours).includes(time)) {
            return json({ ok: false, error: "その日時は受付できません。別の時間をお選びください" }, 400);
          }
        }

        const since = new Date(Date.now() - 10 * 60 * 1000).toISOString();
        const recent = await env.DB.prepare(
          "SELECT COUNT(*) AS c FROM tour_requests WHERE guest_email = ? AND created_at > ?"
        ).bind(guestEmail, since).first();
        if (Number(recent?.c || 0) >= 3) {
          return json({ ok: false, error: "短時間に送信が続いています。しばらくしてからお試しください" }, 429);
        }

        let ownerEmail = "";
        const m = salonIdRaw.match(/^db_(\d+)$/);
        if (m) {
          const row = await env.DB.prepare(
            "SELECT owner_email FROM published_salons WHERE id = ?"
          ).bind(Number(m[1])).first();
          ownerEmail = row?.owner_email || "";
        }
        const adminEmail = env.NOTIFY_EMAIL || "";
        const toOwner = ownerEmail || adminEmail;

        await env.DB.prepare(
          `INSERT INTO tour_requests
            (salon_id, salon_name, owner_email, guest_name, guest_email, guest_phone, desired_date, desired_time, message, status, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'requested', ?)`
        ).bind(
          salonIdRaw, salonName, toOwner, guestName, guestEmail, guestPhone,
          date, time, message, new Date().toISOString()
        ).run();

        const [yy, mm, dd] = date.split("-");
        const when = `${yy}年${Number(mm)}月${Number(dd)}日 ${time}〜（約30分）`;

        const guestText = [
          `${guestName} 様`,
          "",
          "無料見学のリクエストを受け付けました。",
          "オーナーからの返信をお待ちください。",
          "",
          `サロン: ${salonName}`,
          `希望日時: ${when}`,
          message ? `ご要望: ${message}` : "",
          "",
          "※ このメールは送信専用です。",
          "SalonBase",
        ].filter((x) => x !== "").join("\n");

        const ownerText = [
          "無料見学のリクエストが届きました。",
          "",
          `サロン: ${salonName}`,
          `希望日時: ${when}`,
          "",
          `お名前: ${guestName}`,
          `メール: ${guestEmail}`,
          guestPhone ? `電話: ${guestPhone}` : "",
          message ? `ご要望: ${message}` : "",
          "",
          "ご都合を確認のうえ、お客様のメールアドレスへご連絡ください。",
          "SalonBase",
        ].filter((x) => x !== "").join("\n");

        const results = [];
        results.push(await sendMail(env, guestEmail, "【SalonBase】無料見学のリクエストを受け付けました", guestText));
        if (toOwner) {
          results.push(await sendMail(env, toOwner, `【SalonBase】無料見学のリクエスト：${salonName}`, ownerText));
        }
        if (adminEmail && adminEmail !== toOwner) {
          results.push(await sendMail(env, adminEmail, `【SalonBase】（運営控え）無料見学リクエスト：${salonName}`, ownerText));
        }

        return json({ ok: true, mail_sent: results.every(Boolean) });
      } catch (err) {
        return json({ ok: false, error: "見学リクエストの送信に失敗しました" }, 500);
      }
    }
    // ---- サロン予約リクエスト（予約者・サロンオーナー・運営へメール通知） ----
    if (path === "/api/booking" && method === "POST") {
      try {
        const b = await request.json().catch(() => ({}));
        const salonIdRaw = s(b.salon_id, 60);
        const salonName = s(b.salon_name, 150);
        const date = s(b.date, 20);
        const hours = Array.isArray(b.hours)
          ? b.hours.map((h) => s(h, 20)).filter(Boolean)
          : [];
        const hoursCount = Number(b.hours_count) || hours.length || 1;
        const basePrice = Number(b.base_price) || 0;
        const serviceFee = Number(b.service_fee) || 0;
        const totalPrice = Number(b.total_price) || 0;
        const guestName = s(b.guest_name, 100);
        const guestEmail = s(b.guest_email, 200);
        const guestPhone = s(b.guest_phone, 50);

        if (!salonName || !date || hours.length === 0 || !guestName || !guestEmail) {
          return json(
            { ok: false, error: "サロン情報・利用日時・お名前・メールアドレスは必須です" },
            400
          );
        }
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(guestEmail)) {
          return json({ ok: false, error: "メールアドレスの形式が正しくありません" }, 400);
        }

        if (!env.RESEND_API_KEY) {
          return json({ ok: false, error: "メール送信設定（RESEND_API_KEY）が未設定です" }, 500);
        }

        const bookingId = makeBookingCode();
        const timesStr = hours.join(" / ");
        const totalStr = `¥${totalPrice.toLocaleString()}`;

        let ownerEmail = "";
        const m = salonIdRaw.match(/^db_(\d+)$/);
        if (m) {
          try {
            const row = await env.DB.prepare(
              "SELECT owner_email FROM published_salons WHERE id = ?"
            )
              .bind(Number(m[1]))
              .first();
            ownerEmail = row?.owner_email || "";
          } catch (dbErr) {
            console.log("owner_email lookup skipped:", String(dbErr));
          }
        }

        const adminEmail = env.NOTIFY_EMAIL || "";
        const toOwner = ownerEmail || adminEmail;

        const guestSubject = `【SalonBase】予約リクエストを受け付けました：${salonName}`;
        const guestText = [
          `${guestName} 様`,
          "",
          "SalonBase より、サロン予約リクエストを受け付けました。",
          "サロンオーナーからの連絡が来るまで今しばらくお待ちください。",
          "",
          "■ ご予約リクエスト内容",
          `予約番号: ${bookingId}`,
          `サロン名: ${salonName}`,
          `利用日: ${date}`,
          `利用時間: ${timesStr}（計${hoursCount}時間）`,
          `お支払い合計: ${totalStr}`,
          guestPhone ? `電話番号: ${guestPhone}` : "",
          "",
          "※ このメールは送信専用です。",
          "SalonBase",
        ]
          .filter((x) => x !== "")
          .join("\n");

        const sentToGuest = await sendMail(env, guestEmail, guestSubject, guestText);

        if (toOwner) {
          const ownerText = [
            "新しいサロン予約リクエストが届きました。",
            "",
            `予約番号: ${bookingId}`,
            `サロン名: ${salonName}`,
            `利用日: ${date}`,
            `利用時間: ${timesStr}（計${hoursCount}時間）`,
            `お支払い合計: ${totalStr}`,
            "",
            "■ ご予約者情報",
            `お名前: ${guestName} 様`,
            `メール: ${guestEmail}`,
            guestPhone ? `電話: ${guestPhone}` : "",
            "",
            "内容をご確認のうえ、ご予約者へご連絡をお願いいたします。",
            "SalonBase",
          ]
            .filter((x) => x !== "")
            .join("\n");

          await sendMail(
            env,
            toOwner,
            `【SalonBase】新規予約リクエスト：${salonName}（${date} ${timesStr}）`,
            ownerText
          );
        }

        if (adminEmail && adminEmail !== toOwner) {
          const adminText = [
            "（運営控え）新しいサロン予約リクエストが届きました。",
            "",
            `予約番号: ${bookingId}`,
            `サロン名: ${salonName}`,
            `利用日: ${date}`,
            `利用時間: ${timesStr}（計${hoursCount}時間）`,
            `お支払い合計: ${totalStr}`,
            `お名前: ${guestName} 様`,
            `メール: ${guestEmail}`,
            guestPhone ? `電話: ${guestPhone}` : "",
            `送信先オーナー: ${toOwner || "未設定"}`,
          ]
            .filter((x) => x !== "")
            .join("\n");

          await sendMail(
            env,
            adminEmail,
            `【SalonBase】（運営控え）予約リクエスト：${salonName}`,
            adminText
          );
        }

        if (!sentToGuest) {
          return json({ ok: false, error: "確認メールの送信に失敗しました" }, 500);
        }

        return json({ ok: true, booking_id: bookingId }, 201);
      } catch (err) {
        console.log("booking error:", String(err));
        return json({ ok: false, error: "予約リクエストの処理に失敗しました" }, 500);
      }
    }


    // ---- 1. 予約作成 ----
    if (method === "POST" && path === "/api/bookings") {
      const body = await request.json();
      const {
        space_id,
        guest_user_id,
        start_at,
        end_at,
        fee_mode,
        prepay_room = false,
        payment_due_minutes = 15,
      } = body;

      if (!space_id || !guest_user_id || !start_at || !end_at || !FEE_RATE_BPS[fee_mode]) {
        return json({ ok: false, error: "必須項目または fee_mode が不正です" }, 400);
      }
      const startMs = Date.parse(start_at);
      const endMs = Date.parse(end_at);
      if (Number.isNaN(startMs) || Number.isNaN(endMs) || endMs <= startMs) {
        return json({ ok: false, error: "start_at / end_at の日時が不正です" }, 400);
      }

      const space = await env.DB.prepare(
        `SELECT id, salon_id, title, base_price_jpy, is_active
         FROM salon_spaces WHERE id = ?`
      ).bind(space_id).first();

      if (!space || Number(space.is_active) !== 1) {
        return json({ ok: false, error: "利用可能な枠が見つかりません" }, 404);
      }

      const salon = await env.DB.prepare(
        `SELECT id, owner_user_id FROM salons WHERE id = ?`
      ).bind(space.salon_id).first();

      const nowIso = new Date().toISOString();
      const conflict = await env.DB.prepare(
        `SELECT id FROM bookings
         WHERE space_id = ?
           AND (
             status IN ('confirmed', 'completed')
             OR (status = 'pending_payment' AND (payment_due_at IS NULL OR payment_due_at > ?))
           )
           AND NOT (end_at <= ? OR start_at >= ?)
         LIMIT 1`
      ).bind(space_id, nowIso, start_at, end_at).first();

      if (conflict) {
        return json({ ok: false, error: "指定の時間帯はすでに予約または仮押さえされています" }, 409);
      }

      const feeRateBps = FEE_RATE_BPS[fee_mode];
      const roomAmountJpy = Number(space.base_price_jpy);
      const platformFeeJpy = calcFeeJpy(roomAmountJpy, feeRateBps);
      const totalPrepaidJpy = prepay_room ? roomAmountJpy + platformFeeJpy : platformFeeJpy;

      const bookingId = makeId("bkg");
      const bookingCode = makeBookingCode();
      const paymentDueAt = new Date(
        Date.now() + Number(payment_due_minutes) * 60 * 1000
      ).toISOString();

      await env.DB.prepare(
        `INSERT INTO bookings (
          id, booking_code, space_id, salon_id, guest_user_id, host_user_id,
          start_at, end_at, fee_mode, fee_rate_bps,
          room_amount_jpy, platform_fee_jpy, total_prepaid_jpy,
          status, fee_payment_status, payment_due_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending_payment', 'unpaid', ?)`
      ).bind(
        bookingId,
        bookingCode,
        space_id,
        space.salon_id,
        guest_user_id,
        salon?.owner_user_id ?? null,
        start_at,
        end_at,
        fee_mode,
        feeRateBps,
        roomAmountJpy,
        platformFeeJpy,
        totalPrepaidJpy,
        paymentDueAt
      ).run();
        // ---- 予約作成時の管理者・オーナー通知メール ----
        try {
          if (env.RESEND_API_KEY) {
            const notifyTargets = new Set();
            if (env.NOTIFY_EMAIL) notifyTargets.add(env.NOTIFY_EMAIL);

            if (salon?.owner_user_id) {
              const ownerRow = await env.DB.prepare(
                `SELECT email FROM users WHERE id = ?`
              )
                .bind(salon.owner_user_id)
                .first();
              if (ownerRow?.email) notifyTargets.add(ownerRow.email);
            }

            const noticeText = [
              "新しいスペース予約が入りました。",
              "",
              `予約ID: ${bookingId}`,
              `予約コード: ${bookingCode}`,
              `サロンID: ${space.salon_id}`,
              `スペース: ${space.title || space_id}`,
              `開始日時: ${start_at}`,
              `終了日時: ${end_at}`,
              `予約者ID: ${guest_user_id}`,
              `合計金額: ¥${Number(totalPrepaidJpy || 0).toLocaleString()}`,
            ].join("\n");

            for (const toAddr of notifyTargets) {
              await sendMail(
                env,
                toAddr,
                `【SalonBase】新規予約通知：${space.title || space_id}（${start_at}）`,
                noticeText
              );
            }
          }
        } catch (mailErr) {
          console.log("booking notify mail error:", String(mailErr));
        }

      return json({
        ok: true,
        booking_id: bookingId,
        booking_code: bookingCode,
        status: "pending_payment",
        fee_payment_status: "unpaid",
        fee_mode,
        fee_rate_percent: feeRateBps / 100,
        room_amount_jpy: roomAmountJpy,
        platform_fee_jpy: platformFeeJpy,
        total_prepaid_jpy: totalPrepaidJpy,
        payment_due_at: paymentDueAt,
      }, 201);
    }
    // ---- 管理者・オーナー向け：予約＆見学一覧の取得 ----
    if (path === "/api/admin/bookings" && method === "GET") {
      try {
        const auth = await verifyAdminToken(request, env);
        if (!auth) {
          return json({ ok: false, error: "認証が必要です。再ログインしてください" }, 401);
        }

        let bookings = [];
        try {
          const rows = await env.DB.prepare(
            `SELECT id, booking_code, space_id, salon_id, guest_user_id, start_at, end_at, status, total_prepaid_jpy, created_at
             FROM bookings
             ORDER BY created_at DESC
             LIMIT 50`
          ).all();
          bookings = rows.results || [];
        } catch (e) {
          bookings = [];
        }

        let tours = [];
        try {
          const tourRows = await env.DB.prepare(
            `SELECT id, salon_name, applicant_name, email, phone, tour_date, tour_time, note, status, created_at
             FROM tour_bookings
             ORDER BY created_at DESC
             LIMIT 50`
          ).all();
          tours = tourRows.results || [];
        } catch (e) {
          tours = [];
        }

        return json({ ok: true, bookings, tours });
      } catch (err) {
        return json({ ok: false, error: err?.message || "一覧の取得に失敗しました" }, 500);
      }
    }

    // ---- 2. 手数料先払い完了 ----
    const payMatch = path.match(/^\/api\/bookings\/([^/]+)\/pay-fee$/);
    if (method === "POST" && payMatch) {
      const bookingId = payMatch[1];
      const body = await request.json().catch(() => ({}));
      const provider = body.provider || "manual_or_gateway";
      const providerTxId = body.provider_tx_id || null;

      const booking = await env.DB.prepare(
        `SELECT * FROM bookings WHERE id = ?`
      ).bind(bookingId).first();

      if (!booking) return json({ ok: false, error: "予約が見つかりません" }, 404);

      if (booking.status === "confirmed" && booking.fee_payment_status === "paid") {
        return json({ ok: true, message: "すでに先払い完了・確定済みです", booking_id: bookingId });
      }
      if (booking.status !== "pending_payment") {
        return json({ ok: false, error: `現在のステータス（${booking.status}）では先払い確定できません` }, 409);
      }

      const now = new Date();
      if (booking.payment_due_at && Date.parse(booking.payment_due_at) < now.getTime()) {
        return json({ ok: false, error: "先払い期限を過ぎています。予約をやり直してください" }, 410);
      }

      const nowIso = now.toISOString();
      const updated = await env.DB.prepare(
        `UPDATE bookings
         SET status = 'confirmed', fee_payment_status = 'paid', paid_at = ?, updated_at = ?
         WHERE id = ? AND status = 'pending_payment'`
      ).bind(nowIso, nowIso, bookingId).run();

      if (!updated.meta?.changes) {
        return json({ ok: false, error: "予約状態が変更されたため確定できませんでした" }, 409);
      }

      const paymentId = makeId("pay");
      await env.DB.prepare(
        `INSERT INTO booking_payments (
          id, booking_id, tx_type, amount_jpy, provider, provider_tx_id, status
        ) VALUES (?, ?, 'prepay_fee', ?, ?, ?, 'succeeded')`
      ).bind(
        paymentId,
        bookingId,
        Number(booking.total_prepaid_jpy),
        provider,
        providerTxId
      ).run();

      return json({
        ok: true,
        booking_id: bookingId,
        booking_code: booking.booking_code,
        status: "confirmed",
        fee_payment_status: "paid",
        paid_amount_jpy: Number(booking.total_prepaid_jpy),
        payment_id: paymentId,
        paid_at: nowIso,
      });
    }

    // ---- 3. キャンセル ----
    const cancelMatch = path.match(/^\/api\/bookings\/([^/]+)\/cancel$/);
    if (method === "POST" && cancelMatch) {
      const bookingId = cancelMatch[1];
      const body = await request.json().catch(() => ({}));
      const actorUserId = body.actor_user_id || null;
      const actorRole = ["guest", "host", "admin", "system"].includes(body.actor_role)
        ? body.actor_role
        : "guest";
      const reason = body.reason || "";

      const booking = await env.DB.prepare(
        `SELECT b.*, s.free_cancel_before_minutes, s.late_cancel_penalty_bps, s.noshow_penalty_bps
         FROM bookings b
         JOIN salon_spaces s ON s.id = b.space_id
         WHERE b.id = ?`
      ).bind(bookingId).first();

      if (!booking) return json({ ok: false, error: "予約が見つかりません" }, 404);

      if (!["pending_payment", "confirmed"].includes(booking.status)) {
        return json({ ok: false, error: `現在のステータス（${booking.status}）はキャンセルできません` }, 409);
      }

      const now = new Date();
      const nowIso = now.toISOString();
      const minutesBeforeStart = Math.floor((Date.parse(booking.start_at) - now.getTime()) / 60000);
      const freeBeforeMin = Number(booking.free_cancel_before_minutes ?? 1440);
      const latePenaltyBps = Number(booking.late_cancel_penalty_bps ?? 5000);
      const noshowPenaltyBps = Number(booking.noshow_penalty_bps ?? 10000);

      const prepaidAmount = Number(booking.total_prepaid_jpy || 0);
      const isPaid = booking.fee_payment_status === "paid" && prepaidAmount > 0;

      let refundAmount = 0;
      let penaltyAmount = 0;
      let nextFeePaymentStatus = booking.fee_payment_status;
      let policyApplied = "unpaid_cancel";

      if (!isPaid) {
        nextFeePaymentStatus = "unpaid";
        policyApplied = "unpaid_pending_cancel";
      } else if (actorRole === "host" || actorRole === "admin") {
        refundAmount = prepaidAmount;
        nextFeePaymentStatus = "refunded";
        policyApplied = "host_or_admin_full_refund";
      } else if (minutesBeforeStart >= freeBeforeMin) {
        refundAmount = prepaidAmount;
        nextFeePaymentStatus = "refunded";
        policyApplied = "within_free_cancel_window";
      } else if (minutesBeforeStart > 0) {
        penaltyAmount = Math.min(prepaidAmount, calcFeeJpy(prepaidAmount, latePenaltyBps));
        refundAmount = Math.max(0, prepaidAmount - penaltyAmount);
        nextFeePaymentStatus = refundAmount === 0 ? "forfeited" : "partially_refunded";
        policyApplied = "late_cancel_penalty";
      } else {
        penaltyAmount = Math.min(prepaidAmount, calcFeeJpy(prepaidAmount, noshowPenaltyBps));
        refundAmount = Math.max(0, prepaidAmount - penaltyAmount);
        nextFeePaymentStatus = refundAmount === 0 ? "forfeited" : "partially_refunded";
        policyApplied = "past_start_time_penalty";
      }

      const updated = await env.DB.prepare(
        `UPDATE bookings
         SET status = 'cancelled',
             fee_payment_status = ?,
             cancelled_at = ?,
             cancelled_by_role = ?,
             cancel_reason = ?,
             refund_amount_jpy = ?,
             penalty_amount_jpy = ?,
             updated_at = ?
         WHERE id = ? AND status IN ('pending_payment', 'confirmed')`
      ).bind(
        nextFeePaymentStatus,
        nowIso,
        actorRole,
        reason,
        refundAmount,
        penaltyAmount,
        nowIso,
        bookingId
      ).run();

      if (!updated.meta?.changes) {
        return json({ ok: false, error: "キャンセル処理が競合しました" }, 409);
      }

      const logId = makeId("clog");
      await env.DB.prepare(
        `INSERT INTO booking_cancel_logs (
          id, booking_id, actor_user_id, actor_role, minutes_before_start,
          policy_applied, calculated_refund_jpy, calculated_penalty_jpy, note
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
      ).bind(
        logId,
        bookingId,
        actorUserId,
        actorRole,
        minutesBeforeStart,
        policyApplied,
        refundAmount,
        penaltyAmount,
        reason
      ).run();

      if (refundAmount > 0) {
        await env.DB.prepare(
          `INSERT INTO booking_payments (id, booking_id, tx_type, amount_jpy, provider, status)
           VALUES (?, ?, 'refund', ?, 'manual_or_gateway', 'succeeded')`
        ).bind(makeId("pay"), bookingId, refundAmount).run();
      }
      if (penaltyAmount > 0) {
        await env.DB.prepare(
          `INSERT INTO booking_payments (id, booking_id, tx_type, amount_jpy, provider, status)
           VALUES (?, ?, 'penalty_capture', ?, 'manual_or_gateway', 'succeeded')`
        ).bind(makeId("pay"), bookingId, penaltyAmount).run();
      }

      return json({
        ok: true,
        booking_id: bookingId,
        status: "cancelled",
        fee_payment_status: nextFeePaymentStatus,
        minutes_before_start: minutesBeforeStart,
        policy_applied: policyApplied,
        refund_amount_jpy: refundAmount,
        penalty_amount_jpy: penaltyAmount,
        cancel_log_id: logId,
      });
    }

    // ---- 4. 領収書発行 ----
    if (method === "POST" && path === "/api/receipts/issue") {
      const body = await request.json();
      const {
        target_user_id,
        target_role = "guest",
        billing_cycle,
        booking_id = null,
        anchor_date = null,
        recipient_name = "",
        issuer_name = "salon-base",
      } = body;

      if (
        !target_user_id ||
        !["guest", "host"].includes(target_role) ||
        !["per_booking", "half_month", "monthly"].includes(billing_cycle)
      ) {
        return json({ ok: false, error: "必須項目またはパラメータが不正です" }, 400);
      }

      const user = await env.DB.prepare(
        `SELECT id, name, email FROM users WHERE id = ?`
      ).bind(target_user_id).first();
      if (!user) return json({ ok: false, error: "対象ユーザーが見つかりません" }, 404);

      let effectiveAnchorDate = anchor_date;
      if (billing_cycle === "per_booking") {
        if (!booking_id) {
          return json({ ok: false, error: "都度発行（per_booking）には booking_id が必要です" }, 400);
        }
        const targetBooking = await env.DB.prepare(
          `SELECT * FROM bookings WHERE id = ?`
        ).bind(booking_id).first();
        if (!targetBooking) return json({ ok: false, error: "対象予約が見つかりません" }, 404);
        const baseIso = targetBooking.paid_at || targetBooking.start_at || targetBooking.created_at;
        effectiveAnchorDate = effectiveAnchorDate || String(baseIso).slice(0, 10);
      } else {
        effectiveAnchorDate = effectiveAnchorDate || new Date().toISOString().slice(0, 10);
      }

      const period = resolveReceiptPeriod(billing_cycle, effectiveAnchorDate);
      if (!period) {
        return json({ ok: false, error: "対象期間の日付（YYYY-MM-DD）が不正です" }, 400);
      }
      const { periodStartDate, periodEndDate } = period;

      const existing = await env.DB.prepare(
        `SELECT * FROM receipts
         WHERE target_user_id = ? AND target_role = ? AND billing_cycle = ?
           AND period_start_date = ? AND period_end_date = ? AND status = 'issued'
         ORDER BY created_at DESC LIMIT 1`
      ).bind(target_user_id, target_role, billing_cycle, periodStartDate, periodEndDate).first();

      if (existing) {
        const existingItems = await env.DB.prepare(
          `SELECT id, booking_id, booking_payment_id, description, amount_jpy, sort_order
           FROM receipt_items WHERE receipt_id = ? ORDER BY sort_order ASC`
        ).bind(existing.id).all();
        return json({
          ok: true,
          already_issued: true,
          receipt: existing,
          items: existingItems.results || [],
        }, 200);
      }

      const rangeStartIso = `${periodStartDate}T00:00:00.000Z`;
      const rangeEndIso = `${periodEndDate}T23:59:59.999Z`;
      const userCol = target_role === "host" ? "b.host_user_id" : "b.guest_user_id";
      let sql = `
        SELECT bp.id AS payment_id, bp.booking_id, bp.tx_type, bp.amount_jpy, bp.created_at,
               b.booking_code
        FROM booking_payments bp
        JOIN bookings b ON b.id = bp.booking_id
        WHERE bp.status = 'succeeded'
          AND ${userCol} = ?
          AND bp.created_at >= ?
          AND bp.created_at <= ?
      `;
      const binds = [target_user_id, rangeStartIso, rangeEndIso];
      if (billing_cycle === "per_booking" && booking_id) {
        sql += ` AND bp.booking_id = ?`;
        binds.push(booking_id);
      }
      sql += ` ORDER BY bp.created_at ASC`;

      const paymentRows = await env.DB.prepare(sql).bind(...binds).all();
      const rows = paymentRows.results || [];
      if (rows.length === 0) {
        return json({
          ok: false,
          error: "指定期間・条件に該当する決済明細がありません",
          period_start_date: periodStartDate,
          period_end_date: periodEndDate,
        }, 404);
      }

      const formattedItems = rows.map((row, idx) => {
        const info = formatReceiptItemRow(row);
        return {
          id: makeId("ritm"),
          booking_id: row.booking_id,
          booking_payment_id: row.payment_id,
          description: info.description,
          amount_jpy: info.signedAmountJpy,
          sort_order: idx + 1,
        };
      });

      const totalJpy = formattedItems.reduce((sum, it) => sum + Number(it.amount_jpy), 0);
      if (totalJpy <= 0) {
        return json({
          ok: false,
          error: "集計合計が0円以下のため領収書を発行できません",
          total_jpy: totalJpy,
        }, 400);
      }

      const receiptId = makeId("rcp");
      const receiptNo = makeReceiptNo();
      const finalRecipientName =
        String(recipient_name || "").trim() || user.name || user.email || target_user_id;
      const finalIssuer = String(issuer_name || "salon-base").trim() || "salon-base";
      const nowIso = new Date().toISOString();

      await env.DB.prepare(
        `INSERT INTO receipts (
          id, receipt_no, target_user_id, target_role, billing_cycle,
          period_start_date, period_end_date, recipient_name, issuer_name,
          currency, subtotal_jpy, tax_jpy, total_jpy, status, issued_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'JPY', ?, 0, ?, 'issued', ?)`
      ).bind(
        receiptId,
        receiptNo,
        target_user_id,
        target_role,
        billing_cycle,
        periodStartDate,
        periodEndDate,
        finalRecipientName,
        finalIssuer,
        totalJpy,
        totalJpy,
        nowIso
      ).run();

      for (const item of formattedItems) {
        await env.DB.prepare(
          `INSERT INTO receipt_items (
            id, receipt_id, booking_id, booking_payment_id, description, amount_jpy, sort_order
          ) VALUES (?, ?, ?, ?, ?, ?, ?)`
        ).bind(
          item.id,
          receiptId,
          item.booking_id,
          item.booking_payment_id,
          item.description,
          item.amount_jpy,
          item.sort_order
        ).run();
      }

      return json({
        ok: true,
        already_issued: false,
        receipt: {
          id: receiptId,
          receipt_no: receiptNo,
          target_user_id,
          target_role,
          billing_cycle,
          period_start_date: periodStartDate,
          period_end_date: periodEndDate,
          recipient_name: finalRecipientName,
          issuer_name: finalIssuer,
          currency: "JPY",
          subtotal_jpy: totalJpy,
          tax_jpy: 0,
          total_jpy: totalJpy,
          status: "issued",
          issued_at: nowIso,
        },
        items: formattedItems,
      }, 201);
    }

    // ---- 5. 領収書取得 ----
    const receiptMatch = path.match(/^\/api\/receipts\/([^/]+)$/);
    if (method === "GET" && receiptMatch) {
      const receiptId = receiptMatch[1];
      const receipt = await env.DB.prepare(
        `SELECT * FROM receipts WHERE id = ?`
      ).bind(receiptId).first();
      if (!receipt) return json({ ok: false, error: "領収書が見つかりません" }, 404);
      const items = await env.DB.prepare(
        `SELECT id, booking_id, booking_payment_id, description, amount_jpy, sort_order
         FROM receipt_items WHERE receipt_id = ? ORDER BY sort_order ASC`
      ).bind(receiptId).all();
      return json({ ok: true, receipt, items: items.results || [] });
    }

    // ---- それ以外は画面（HTMLなど）を返す ----
    if (path.startsWith("/api/")) {
      return json({ ok: false, error: "Not Found" }, 404);
    }
    return env.ASSETS.fetch(request);
  },
};

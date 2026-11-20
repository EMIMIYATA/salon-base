const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json" },
  });

const s = (v, n = 300) => String(v || "").trim().slice(0, n);

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

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
            const text = [
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
                        const r = await fetch("https://api.resend.com/emails", {
              method: "POST",
              headers: {
                Authorization: `Bearer ${env.RESEND_API_KEY}`,
                "content-type": "application/json",
              },
              body: JSON.stringify({
                from: "SalonBase <noreply@send.weblavo-tokyo.com>",
                to: [env.NOTIFY_EMAIL],
                subject: `【SalonBase】新規エントリー: ${salon}`,
                text,
              }),
            });
            if (!r.ok) console.log("resend error", r.status, await r.text());

                
          }
        } catch (e) {}

        return json({ ok: true });
      } catch (e) {
        return json({ ok: false, error: "保存に失敗しました" }, 500);
      }
    }

    return env.ASSETS.fetch(request);
  },
};

import { useEffect, useRef, useState } from "react";
import { io } from "socket.io-client";
import { api, getToken } from "../lib/api";
import {
  loadSessionKey,
  decryptWithSessionKey,
  encryptWithSessionKey,
  decryptVault,
  cacheSessionKey,
  loadPrivateJwk,
  cachePrivateJwk,
  deriveConversationAesKey,
  encryptWithDerivedKey,
  decryptWithDerivedKey,
} from "../lib/crypto";

export default function Chat() {
  const [me, setMe] = useState(null);
  const [users, setUsers] = useState([]);
  const [online, setOnline] = useState({});
  const [peer, setPeer] = useState(null);
  const [messages, setMessages] = useState([]);
  const [text, setText] = useState("");
  const [needPin, setNeedPin] = useState(false);
  const [vault, setVault] = useState(null);
  const [pin, setPin] = useState("");
  const [myPrivJwk, setMyPrivJwk] = useState(null);
  const [refreshMessages, setRefreshMessages] = useState(0);
  const socketRef = useRef(null);

  // Load me, vault, and users
  useEffect(() => {
    (async () => {
      try {
        const { user, encryptedVault } = await api("/auth/me");
        setMe(user);
        setVault(encryptedVault);

        const cachedPriv = loadPrivateJwk();
        if (cachedPriv) setMyPrivJwk(cachedPriv);

        const sess = loadSessionKey();
        if (!sess && !cachedPriv) setNeedPin(true);

        const u = await api("/users");
        setUsers(u.users.filter((x) => x.id !== user.id));
      } catch {
        window.location.href = "/login";
      }
    })();
  }, []);

  // Socket for presence and realtime messages
  useEffect(() => {
    const token = getToken();
    if (!token || socketRef.current) return;

    const s = io("http://localhost:4000", { auth: { token } });
    socketRef.current = s;

    s.on("presence", ({ userId, online: isOn }) =>
      setOnline((prev) => ({ ...prev, [userId]: isOn }))
    );
    s.on("chat", async (msg) => {
      const senderId =
        typeof msg.sender === "string"
          ? msg.sender
          : msg.sender?._id || msg.sender?.id || String(msg.sender || "");

      const receiverId = msg.receiverId || msg.to; // adjust if your backend uses a different field

      const isFromMe = senderId && me?.id && String(senderId) === String(me.id);

      // Only append if message belongs to current peer conversation
      if (
        (peer &&
          (senderId === (peer._id || peer.id) || receiverId === me?.id)) ||
        isFromMe
      ) {
        setMessages((prev) => [...prev, msg]);
      }

      // Refresh users if needed
      if (!isFromMe) {
        const known = users.find(
          (u) => String(u._id || u.id) === String(senderId)
        );
        if (!known || !known.ecdhPublicJwk) {
          try {
            const ures = await api("/users");
            setUsers(ures.users.filter((u) => u.id !== me?.id));
          } catch {}
        }
      }
    });

    return () => {
      s.disconnect();
      socketRef.current = null;
    };
  }, [me, users]);

  // Load conversation with a user
  async function loadConversation(u) {
    try {
      const ures = await api("/users");
      const list = ures.users.filter((x) => x.id !== me?.id);
      setUsers(list);

      const updated =
        list.find((x) => String(x.id) === String(u._id || u.id)) || u;
      setPeer(updated);
    } catch {
      setPeer(u);
    }

    const res = await api(`/messages/${u._id || u.id}`);
    setMessages(res.messages || []);
  }

  // Send message
  async function send() {
    try {
      const sess = loadSessionKey();
      const hasECDH = myPrivJwk && peer?.ecdhPublicJwk;

      if (!sess && !hasECDH) {
        setNeedPin(true);
        return;
      }
      if (!text.trim() || !peer) return;

      let payload;
      if (hasECDH) {
        const aesKey = await deriveConversationAesKey(
          myPrivJwk,
          peer.ecdhPublicJwk
        );
        payload = await encryptWithDerivedKey(text, aesKey);
      } else {
        payload = await encryptWithSessionKey(text, sess);
      }

      await api("/messages", {
        method: "POST",
        body: JSON.stringify({
          receiverId: peer._id || peer.id,
          encryptedContent: JSON.stringify(payload),
        }),
      });
      setText("");
    } catch (e) {
      alert(e.message);
    }
  }

  // Get peer's public key dynamically
  async function getPeerPublicKey(userId) {
    const cached = users.find((u) => String(u._id || u.id) === String(userId));
    if (cached?.ecdhPublicJwk) return cached.ecdhPublicJwk;

    try {
      const ures = await api("/users");
      setUsers(ures.users.filter((u) => u.id !== me?.id));
      const updated = ures.users.find((u) => String(u.id) === String(userId));
      return updated?.ecdhPublicJwk;
    } catch {
      return null;
    }
  }

  // Render message content
  async function renderContent(m) {
    try {
      const sess = loadSessionKey();
      const payload =
        typeof m.encryptedContent === "string"
          ? JSON.parse(m.encryptedContent)
          : m.encryptedContent;

      const senderId =
        typeof m.sender === "string"
          ? m.sender
          : m.sender?._id || m.sender?.id || String(m.sender || "");
      const isFromMe = senderId && me?.id && String(senderId) === String(me.id);

      // If no keys yet, wait
      if (!myPrivJwk && !sess) return null;

      // Try ECDH
      if (myPrivJwk) {
        const theirPub = isFromMe
          ? peer?.ecdhPublicJwk
          : await getPeerPublicKey(senderId);

        if (!theirPub) return null; // wait for peer key

        try {
          const aesKey = await deriveConversationAesKey(myPrivJwk, theirPub);
          return await decryptWithDerivedKey(payload, aesKey);
        } catch (e) {
          console.log("ECDH decrypt failed", e);
        }
      }

      // Try session key
      if (sess) {
        try {
          return await decryptWithSessionKey(payload, sess);
        } catch (e) {
          console.log("Session key decrypt failed", e);
        }
      }

      return "[locked]";
    } catch (err) {
      console.log("Render content error:", err);
      return "[ ERROR ! ]";
    }
  }

  // Unlock vault with PIN
  async function unlock() {
    try {
      if (!vault) throw new Error("Missing vault");
      const result = await decryptVault(vault, pin);

      if (result?.ecdhPrivateJwk) {
        cachePrivateJwk(result.ecdhPrivateJwk, 5 * 60 * 1000);
        setMyPrivJwk(result.ecdhPrivateJwk);
      }

      if (result?.legacySessionKeyHex) {
        cacheSessionKey(result.legacySessionKeyHex, 3 * 60 * 1000);
        try {
          await api("/auth/migrate-ecdh", {
            method: "POST",
            body: JSON.stringify({ pin }),
          });
          const u = await api("/users");
          setUsers(u.users.filter((x) => x.id !== me.id));
          const meRes = await api("/auth/me");
          setVault(meRes.encryptedVault);
          const migrated = await decryptVault(meRes.encryptedVault, pin);
          if (migrated?.ecdhPrivateJwk) {
            cachePrivateJwk(migrated.ecdhPrivateJwk, 5 * 60 * 1000);
            setMyPrivJwk(migrated.ecdhPrivateJwk);
          }
        } catch {}
      }

      setNeedPin(false);
      setPin("");
      setRefreshMessages((r) => r + 1); // retry decryption for all messages
    } catch {
      alert("Invalid PIN");
    }
  }

  return (
    <div className="flex h-screen">
      <div className="w-64 border-r p-4 space-y-2 overflow-auto">
        <div className="font-bold">Users</div>
        {users.map((u) => (
          <button
            key={u._id || u.id}
            className={`w-full text-left p-2 border ${
              peer && (peer._id || peer.id) === (u._id || u.id)
                ? "bg-blue-50"
                : ""
            }`}
            onClick={() => loadConversation(u)}
          >
            <span
              className={`inline-block w-2 h-2 rounded-full mr-2 ${
                online[u._id || u.id] ? "bg-green-500" : "bg-gray-400"
              }`}
            ></span>
            {u.username}
          </button>
        ))}
      </div>

      <div className="flex-1 flex flex-col">
        {peer && (
          <div className="p-2 border-b text-xs bg-gray-50 text-gray-700">
            {myPrivJwk ? (
              peer.ecdhPublicJwk ? (
                <span className="text-green-700">
                  End-to-end encryption: active (ECDH)
                </span>
              ) : (
                <span className="text-orange-700">
                  Peer hasn't unlocked yet. Ask them to login and enter their
                  PIN.
                </span>
              )
            ) : (
              <span className="text-orange-700">
                Unlock with your PIN to enable decryption.
              </span>
            )}
          </div>
        )}

        {needPin && (
          <div className="p-4 border-b bg-yellow-50 flex items-center gap-2">
            <span className="text-sm">
              Session locked. Enter PIN to decrypt:
            </span>
            <input
              className="border p-2"
              type="password"
              value={pin}
              onChange={(e) => setPin(e.target.value)}
              placeholder="PIN"
            />
            <button
              className="bg-green-600 text-white px-3 py-2"
              onClick={unlock}
            >
              Unlock
            </button>
          </div>
        )}

        <div className="flex-1 overflow-auto p-4 space-y-2">
          {messages.map((m, i) => (
            <div key={i} className="p-2 bg-white border rounded">
              <div className="text-xs text-gray-500">
                {m.sender === me?.id ? "You" : "Peer"}
              </div>
              <MessageContent
                msg={m}
                renderContent={renderContent}
                refresh={refreshMessages}
              />
            </div>
          ))}
        </div>

        <div className="p-4 border-t flex gap-2">
          <input
            className="flex-1 border p-2"
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder={needPin ? "Enter PIN to unlock above" : "Type message"}
          />
          <button
            className="bg-blue-600 text-white px-4 py-2"
            onClick={send}
            disabled={!peer}
          >
            Send
          </button>
        </div>
      </div>
    </div>
  );
}

function MessageContent({ msg, renderContent, refresh }) {
  const [text, setText] = useState(null);

  useEffect(() => {
    let mounted = true;
    (async () => {
      const t = await renderContent(msg);
      if (mounted) setText(t);
    })();
    return () => (mounted = false);
  }, [msg, renderContent, refresh]);

  if (text === null) return <div className="text-gray-400">Decrypting...</div>;

  return <div>{text}</div>;
}

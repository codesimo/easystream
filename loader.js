async function decryptBundle(bundle, passphrase) {
  console.log('[DEBUG] Decrypting bundle...');
  console.log('[DEBUG] Salt:', bundle.salt);
  console.log('[DEBUG] IV:', bundle.iv);
  console.log('[DEBUG] Iterations:', bundle.iterations);

  const encoder = new TextEncoder();

  try {
    const salt = Uint8Array.from(atob(bundle.salt), c => c.charCodeAt(0));
    const iv = Uint8Array.from(atob(bundle.iv), c => c.charCodeAt(0));
    const tag = Uint8Array.from(atob(bundle.tag), c => c.charCodeAt(0));
    const ciphertext = Uint8Array.from(atob(bundle.ciphertext), c => c.charCodeAt(0));

    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      encoder.encode(passphrase),
      { name: "PBKDF2", hash: "SHA-256" },
      false,
      ["deriveKey"]
    );

    const key = await crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt,
        iterations: bundle.iterations,
        hash: "SHA-256"
      },
      keyMaterial,
      {
        name: "AES-GCM",
        length: 256
      },
      false,
      ["decrypt"]
    );

    const combined = new Uint8Array(ciphertext.length + tag.length);
    combined.set(ciphertext);
    combined.set(tag, ciphertext.length);

    const decrypted = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv
      },
      key,
      combined
    );

    const decryptedText = new TextDecoder().decode(decrypted);

    console.log('[DEBUG] Decryption successful!');
    console.log('[DEBUG] Decrypted content length:', decryptedText.length);

    return decryptedText;
  } catch (error) {
    console.error('[ERROR] Decryption failed:', error.message);
    throw error;
  }
}

async function runEncryptedScript() {
  const response = await fetch("enc.bundle.json");
  const bundle = await response.json();

  // Check if we have a saved password in localStorage
  let userPassword;
  try {
    userPassword = localStorage.getItem("decoded_password") || "";
  } catch (e) {
    // Storage not available, use empty string to show popup
  }

  // Show password input popup only if no saved password exists
  if (!userPassword) {
    const popup = document.createElement("div");
    popup.style.cssText = `
      position: fixed;
      top: 50%;
      left: 50%;
      transform: translate(-50%, -50%);
      background: white;
      padding: 20px;
      border-radius: 8px;
      box-shadow: 0 4px 6px rgba(0,0,0,0.1);
      z-index: 999999;
      font-family: Arial, sans-serif;
      min-width: 300px;
    `;

    popup.innerHTML = `
      <h3 style="margin-top: 0; margin-bottom: 15px;">Decryption Password</h3>
      <p style="margin-bottom: 15px;">Please enter the decoding password:</p>
      <input 
        type="password" 
        id="passwordInput" 
        placeholder="Enter password"
        style="width: 100%; padding: 8px; margin-bottom: 10px; box-sizing: border-box;"
        autofocus
      />
      <button 
        id="decryptBtn"
        style="width: 100%; padding: 10px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer;"
      >
        Decrypt
      </button>
    `;

    document.body.appendChild(popup);

    const passwordInput = popup.querySelector("#passwordInput");
    const decryptBtn = popup.querySelector("#decryptBtn");

    // Handle decryption button click
    decryptBtn.addEventListener("click", async () => {
      const userPassword = passwordInput.value.trim();

      if (!userPassword) {
        alert("Please enter a password.");
        return;
      }

      decryptBtn.disabled = true;
      decryptBtn.textContent = "Decrypting...";

      try {
        const source = await decryptBundle(bundle, userPassword);

        // Save decoded password to localStorage for future visits
        localStorage.setItem("decoded_password", userPassword);

        // Decrypt successful - run the code and close popup
        (new Function(source))();
        document.body.removeChild(popup);
      } catch (error) {
        console.error('[ERROR] Decryption error details:', error.message);
        console.error('[ERROR] Stack trace:', error.stack);
        alert("Decryption failed with the provided password. Please try again.");
        decryptBtn.disabled = false;
        decryptBtn.textContent = "Decrypt";
      }
    });

    // Handle Enter key
    passwordInput.addEventListener("keypress", (e) => {
      if (e.key === "Enter") {
        decryptBtn.click();
      }
    });
  } else {
    console.log("Using previously saved decryption password.");

    // Decrypt using the saved password and run the script
    try {
      const source = await decryptBundle(bundle, userPassword);

      console.log('[DEBUG] Decryption successful!');
      console.log('[DEBUG] Decrypted content length:', source.length);


      // Execute the decrypted code
      (new Function(source))();
    } catch (error) {
      console.error('[ERROR] Decryption error details:', error.message);
      console.error('[ERROR] Stack trace:', error.stack);
      alert("Decryption failed with the saved password. Please try again.");
      popup.innerHTML = `
        <h3 style="margin-top: 0; margin-bottom: 15px;">Error</h3>
        <p style="margin-bottom: 15px;">${error.message}</p>
        <button 
          onclick="location.reload()"
          style="width: 100%; padding: 10px; background: #dc3545; color: white; border: none; border-radius: 4px; cursor: pointer;"
        >
          Reload Page
        </button>
      `;
    }
  }
}

runEncryptedScript();

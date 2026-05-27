using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace siwan1.Pages
{
    [IgnoreAntiforgeryToken]
    public class IndexModel : PageModel
    {
        public void OnGet()
        {
        }

        // 🛡️ 1. دالة هاندلر التشفير
        public async Task<IActionResult> OnPostEncryptAsync(IFormFile uploadedFile, string password)
        {
            if (uploadedFile == null || uploadedFile.Length == 0 || string.IsNullOrEmpty(password))
            {
                ModelState.AddModelError(string.Empty, "يرجى اختيار ملف وإدخال كلمة المرور.");
                return Page();
            }

            try
            {
                byte[] fileBytes;
                using (var ms = new MemoryStream())
                {
                    await uploadedFile.CopyToAsync(ms);
                    fileBytes = ms.ToArray();
                }

                byte[] encryptedBytes = EncryptBytes(fileBytes, password);
                string encryptedFileName = uploadedFile.FileName + ".siwan";

                return File(encryptedBytes, "application/octet-stream", encryptedFileName);
            }
            catch (Exception ex)
            {
                ModelState.AddModelError(string.Empty, "حدث خطأ أثناء التشفير: " + ex.Message);
                return Page();
            }
        }

        // 🔓 2. دالة هاندلر فك التشفير
        public async Task<IActionResult> OnPostDecryptAsync(IFormFile uploadedFile, string password)
        {
            if (uploadedFile == null || uploadedFile.Length == 0 || string.IsNullOrEmpty(password))
            {
                ModelState.AddModelError(string.Empty, "يرجى اختيار الملف المشفر وإدخال كلمة المرور.");
                return Page();
            }

            try
            {
                byte[] fileBytes;
                using (var ms = new MemoryStream())
                {
                    await uploadedFile.CopyToAsync(ms);
                    fileBytes = ms.ToArray();
                }

                byte[] decryptedBytes = DecryptBytes(fileBytes, password);

                // استرجاع الاسم الأصلي وحذف امتداد .siwan لو وجد
                string originalFileName = uploadedFile.FileName;
                if (originalFileName.EndsWith(".siwan", StringComparison.OrdinalIgnoreCase))
                {
                    originalFileName = originalFileName.Substring(0, originalFileName.Length - 6);
                }

                return File(decryptedBytes, "application/octet-stream", originalFileName);
            }
            catch (Exception ex)
            {
                ModelState.AddModelError(string.Empty, "فشل فك التشفير! تأكدي من صحة كلمة المرور أو سلامة الملف. " + ex.Message);
                return Page();
            }
        }

        // --- خوارزمية التشفير بـ AES-256 ---
        private byte[] EncryptBytes(byte[] bytesToBeEncrypted, string password)
        {
            byte[] passwordBytes = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(password));

            using (Aes aes = Aes.Create())
            {
                aes.KeySize = 256;
                aes.BlockSize = 128;

                var key = new byte[32];
                Array.Copy(passwordBytes, 0, key, 0, 32);
                aes.Key = key;
                aes.IV = new byte[16];

                using (var ms = new MemoryStream())
                {
                    using (var cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(bytesToBeEncrypted, 0, bytesToBeEncrypted.Length);
                        cs.FlushFinalBlock();
                    }
                    return ms.ToArray();
                }
            }
        }

        // --- خوارزمية فك التشفير بـ AES-256 ---
        private byte[] DecryptBytes(byte[] bytesToBeDecrypted, string password)
        {
            byte[] passwordBytes = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(password));

            using (Aes aes = Aes.Create())
            {
                aes.KeySize = 256;
                aes.BlockSize = 128;

                var key = new byte[32];
                Array.Copy(passwordBytes, 0, key, 0, 32);
                aes.Key = key;
                aes.IV = new byte[16];

                using (var ms = new MemoryStream())
                {
                    using (var cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(bytesToBeDecrypted, 0, bytesToBeDecrypted.Length);
                        cs.FlushFinalBlock();
                    }
                    return ms.ToArray();
                }
            }
        }
    }
}
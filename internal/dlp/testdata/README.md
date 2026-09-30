Synthetic fixtures for the DLP converter/OCR tests. All personal data in
them is fake (resident number 900101-1234567 is a made-up test value).

| file | contents |
|---|---|
| rrn.heic, rrn.avif | photo-style image of the text (HEIF / AVIF) |
| rrn-ccitt.pdf | scanned page, CCITT Group 4 (`/BlackIs1 true`) |
| rrn-bilevel.pdf | scanned page, 1-bit Flate with PNG predictor |
| rrn-jpx.pdf | scanned page, JPEG 2000 (needs poppler to render) |
| rrn-owner-pw.pdf | text layer, owner password only (opens without password) |
| rrn-user-pw.pdf | text layer, user password `open-sesame` (cannot be opened) |
| rrn.txt.gz, rrn.tar.gz | resident number inside gzip / tar.gz |
| rrn.7z | resident number inside an unencrypted 7z archive |
| rrn-enc.7z, rrn-enc.zip | password-protected 7z / AES-256 zip (password SECRET) |

Regenerate with Pillow, img2pdf, pikepdf and `heif-enc` (see git history).

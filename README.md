# YUSUF BARIŞ DURMUŞ - Sistem Log Analiz ve İzleme Aracı

Bu proje, Linux sistem loglarını (auth.log, syslog vb.) gerçek zamanlı izleyen, belirlenen tehdit kurallarına göre analiz eden ve web tabanlı bir arayüzde raporlayan bir siber güvenlik yazılımıdır.

## Özellikler

*   **Canlı İzleme:** Loglar WebSocket üzerinden anlık olarak arayüze akar.
*   **Kural Motoru:** Regex tabanlı imzalar ile saldırı tespiti (Brute Force, Root Login vb.).
*   **Korelasyon:** Birden fazla olayı birleştirerek gelişmiş tehdit analizi.
*   **Güvenli Erişim:** Rol tabanlı (Admin/User) kullanıcı yönetimi.
*   **Raporlama:** Geçmiş olayların CSV formatında dışa aktarımı log bilgileri (hangi kullanıcılar tarafından CSV dosyası çıkarıldı).

```
┌─────────────────┐
│   CLI Engine    │ ──┐
│                 │   │
└─────────────────┘   │
                      ├──► SQLite DB ◄──┐
┌─────────────────┐   │                 │
│  Live Tailer    │ ──┘                 │
│                 │                     │
└─────────────────┘                     │
                                        │
┌─────────────────┐                     │
│  FastAPI Server │ ────────────────────┘
│                 │
└─────────────────┘
        │
        ▼
┌─────────────────┐
│  Web Dashboard  │
│                 │
└─────────────────┘
```

## Kurulum

Sistemi çalıştırmanın en kolay yolu Docker kullanmaktır.

### Gereksinimler

*   Docker ve Docker Compose

### Çalıştırma Adımları

1.  Terminali proje dizininde açın.
2.  Aşağıdaki komutu çalıştırın:

    ```bash
    docker-compose up -d --build
    ```

3.  Tarayıcınızdan şu adrese gidin: `http://localhost:8000`

### Varsayılan Giriş Bilgileri

*   **Kullanıcı Adı:** admin
*   **Şifre:** admin123

(İlk kurulumda bu kullanıcı otomatik oluşturulur. Giriş yaptıktan sonra yeni kullanıcılar ekleyebilirsiniz.)

### Web Paneli

1. http://localhost:8000 adresine gidin
2. Kullanıcı: `admin`, Şifre: `admin123`
3. Dashboard'da sistem durumunu görüntüleyin
4. "Olay Akışı" sekmesinden detaylı logları inceleyin
5. "Kural Yönetimi" ile kuralları aktif/pasif yapın

## Manuel Kurulum (Geliştirme Amaçlı)

Docker kullanmadan çalıştırmak isterseniz:

1.  Python sanal ortamını oluşturun ve aktif edin.
2.  Gerekli paketleri yükleyin:
    ```bash
    pip install -r requirements.txt
    ```
3.  Veritabanını ve ilk ayarları oluşturun:
    ```bash
    python init_system.py
    ```
4.  Servisleri başlatın (İki ayrı terminalde çalıştırılmalıdır):

    *   **Terminal 1 (Log İzleyici):**
        ```bash
        python daemon.py
        ```

    *   **Terminal 2 (Web Sunucusu):**
        ```bash
        python api.py
        ```

## Güvenlik Notları

**ÜRETİM İÇİN YAPILMASI GEREKENLER:**
1. `api.py` içindeki `SECRET_KEY` değiştirin
2. Admin şifresini değiştirin
3. HTTPS kullanın (reverse proxy ile)
4. Firewall kuralları ekleyin (port 8000)
5. Rate limiting değerlerini ayarlayın

## Proje Yapısı

*   **api.py:** Web sunucusu ve API (FastAPI).
*   **daemon.py:** Arka planda logları okuyan servis.
*   **analyzer.py:** Log satırlarını analiz eden motor.
*   **correlation.py:** Olay ilişkilendirme motoru.
*   **rules.json:** Tespit kurallarının tanımlandığı dosya.
*   **config.json:** Log dosyalarının yolları ve ayarlar.

## Katkıda Bulunma

Bu proje akademik amaçlıdır. Önerileriniz için issue açabilirsiniz.

---
Geliştirici: YUSUF BARIŞ DURMUŞ


# YUSUF BARIŞ DURMUŞ - Sistem Log Analiz ve İzleme Aracı

Bu proje, Linux sistem loglarını (auth.log, syslog vb.) gerçek zamanlı izleyen, belirlenen tehdit kurallarına göre analiz eden ve web tabanlı bir arayüzde raporlayan bir siber güvenlik yazılımıdır.

## Özellikler

*   **Canlı İzleme:** Loglar WebSocket üzerinden anlık olarak arayüze akar.
*   **Kural Motoru:** Regex tabanlı imzalar ile saldırı tespiti (Brute Force, Root Login vb.).
*   **Korelasyon:** Birden fazla olayı birleştirerek gelişmiş tehdit analizi.
*   **Güvenli Erişim:** Rol tabanlı (Admin/User) kullanıcı yönetimi.
*   **Raporlama:** Geçmiş olayların CSV formatında dışa aktarımı log bilgileri (hangi kullanıcılar tarafından CSV dosyası çıkarıldı).

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

## Proje Yapısı

*   **api.py:** Web sunucusu ve API (FastAPI).
*   **daemon.py:** Arka planda logları okuyan servis.
*   **analyzer.py:** Log satırlarını analiz eden motor.
*   **correlation.py:** Olay ilişkilendirme motoru.
*   **rules.json:** Tespit kurallarının tanımlandığı dosya.
*   **config.json:** Log dosyalarının yolları ve ayarlar.

---
Geliştirici: YUSUF BARIŞ DURMUŞ

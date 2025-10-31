# main.py (بدون تغییر - سازگار با هر دو نسخه ربات)

import logging
import routeros_api
from routeros_api.exceptions import RouterOsApiConnectionError

# راه‌اندازی سیستم لاگ برای ثبت خطاها
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("main_logs.log", encoding="utf-8"), logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

class RouterOSManager:
    """
    کلاسی برای مدیریت کامل روتر میکروتیک (نسخه ۷ و بالاتر) از طریق API و پکیج User Manager.
    """
    def __init__(self, host, port, username, password):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.connection = None

    def _connect(self) -> bool:
        if self.connection:
            return True
        try:
            self.connection = routeros_api.RouterOsApiPool(
                host=self.host,
                username=self.username,
                password=self.password,
                port=self.port,
                plaintext_login=True
            )
            api = self.connection.get_api()
            api.get_resource('/system/resource').get()
            logger.info(f"اتصال به میکروتیک {self.host} (RouterOS v7 - User Manager) با موفقیت برقرار شد.")
            return True
        except RouterOsApiConnectionError as e:
            logger.error(f"خطا در اتصال به میکروتیک {self.host}: {e}")
            self.connection = None
            return False
        except Exception as e:
            logger.error(f"یک خطای پیش‌بینی نشده در اتصال به میکروتیک رخ داد: {e}")
            self.connection = None
            return False

    def close(self):
        if self.connection:
            self.connection.disconnect()
            self.connection = None
            logger.info("اتصال به میکروتیک بسته شد.")

    def get_all_users(self) -> list | None:
        if not self._connect():
            return None
        try:
            api = self.connection.get_api()
            users = api.get_resource('/user-manager/user').get()
            return users
        except Exception as e:
            logger.error(f"خطا در دریافت لیست کاربران از User Manager v7: {e}")
            return None

    def get_user_details(self, username: str) -> dict | None:
        """
        آمار کلی و دقیق کاربر را با استفاده از دستور monitor ... once استخراج می‌کند.
        این روش صحیح و کامل برای دریافت آمار کاربران آنلاین و آفلاین است.
        """
        if not self._connect():
            return None
        try:
            api = self.connection.get_api()
            user_resource = api.get_resource('/user-manager/user')

            user_list = user_resource.get(name=username)
            if not user_list:
                return None  # کاربر یافت نشد

            user_id = user_list[0]['id']
            
            # اجرای دستور monitor once برای دریافت اطلاعات کامل
            monitor_result = user_resource.call('monitor', {'numbers': user_id, 'once': ''})

            # اطلاعات پایه را به عنوان پیش‌فرض در نظر می‌گیریم
            final_details = user_list[0]
            
            # اگر مانیتورینگ نتیجه‌ای داشت، آن را با اطلاعات پایه ترکیب می‌کنیم
            if monitor_result:
                final_details.update(monitor_result[0])

            return final_details

        except Exception as e:
            logger.error(f"خطا در دریافت اطلاعات مانیتورینگ کاربر '{username}': {e}. این خطا معمولا به دلیل سطح دسترسی ناکافی کاربر API است.")
            # در صورت خطا در مانیتور، اطلاعات پایه را برمی‌گرداند
            try:
                api = self.connection.get_api()
                user_list = api.get_resource('/user-manager/user').get(name=username)
                return user_list[0] if user_list else None
            except:
                return None

    def create_user_with_profile(self, username, password, profile, **kwargs) -> bool:
        """
        کاربر را در دو مرحله می‌سازد: ۱. ساخت کاربر پایه ۲. اتصال پروفایل با user-profile
        """
        if not self._connect():
            return False
        api = self.connection.get_api()
        try:
            shared_users_val = kwargs.get('shared_users', 1)
            user_params = {
                'name': username,
                'password': password,
                'shared-users': str(shared_users_val),
            }
            api.get_resource('/user-manager/user').add(**user_params)
            logger.info(f"مرحله ۱: کاربر پایه '{username}' ساخته شد.")

            profile_params = {
                'user': username,
                'profile': profile
            }
            api.get_resource('/user-manager/user-profile').add(**profile_params)
            logger.info(f"مرحله ۲: پروفایل '{profile}' به کاربر '{username}' از طریق user-profile متصل شد.")

            return True
        except Exception as e:
            # در صورت خطا، کاربر ناقص ساخته شده را حذف می‌کند
            try:
                user_list = api.get_resource('/user-manager/user').get(name=username)
                if user_list:
                    api.get_resource('/user-manager/user').remove(id=user_list[0]['id'])
                    logger.warning(f"کاربر ناقص '{username}' به دلیل خطا در ساخت، حذف شد.")
            except Exception as cleanup_e:
                logger.error(f"خطا در پاک کردن کاربر ناقص '{username}': {cleanup_e}")

            logger.error(f"خطا در فرآیند ساخت کاربر '{username}' در User Manager v7: {e}")
            return False

    def change_user_password(self, username, new_password) -> bool:
        if not self._connect():
            return False
        try:
            api = self.connection.get_api()
            user_list = api.get_resource('/user-manager/user').get(name=username)
            if not user_list:
                logger.warning(f"کاربر '{username}' برای تغییر رمز عبور یافت نشد.")
                return False
            user_id = user_list[0]['id']
            api.get_resource('/user-manager/user').set(id=user_id, password=new_password)
            logger.info(f"رمز عبور کاربر '{username}' با موفقیت تغییر کرد.")
            return True
        except Exception as e:
            logger.error(f"خطا در تغییر رمز عبور کاربر '{username}': {e}")
            return False

    def get_all_profiles(self) -> list | None:
        if not self._connect():
            return None
        try:
            api = self.connection.get_api()
            profiles = api.get_resource('/user-manager/profile').get()
            return profiles
        except Exception as e:
            logger.error(f"خطا در دریافت لیست پروفایل‌ها از User Manager v7: {e}")
            return None

    def renew_user_by_recreating(self, username, new_password, new_profile, **kwargs) -> bool:
        if not self._connect():
            return False
        try:
            api = self.connection.get_api()
            user_list = api.get_resource('/user-manager/user').get(name=username)
            if not user_list:
                logger.warning(f"کاربری با نام '{username}' برای تمدید یافت نشد.")
                return False
            user_id = user_list[0]['id']

            shared_users_val = kwargs.get('shared_users', 1)

            # آپدیت رمز و اطلاعات کاربر
            api.get_resource('/user-manager/user').set(
                id=user_id,
                password=new_password,
                **{'shared-users': str(shared_users_val)}
            )

            # آپدیت پروفایل
            profile_link_list = api.get_resource('/user-manager/user-profile').get(user=username)
            if profile_link_list:
                profile_link_id = profile_link_list[0]['id']
                api.get_resource('/user-manager/user-profile').set(id=profile_link_id, profile=new_profile)
            else: # اگر به هر دلیلی لینک پروفایل وجود نداشت، یکی جدید می‌سازد
                api.get_resource('/user-manager/user-profile').add(user=username, profile=new_profile)

            # ریست کردن آمار مصرف
            api.get_resource('/user-manager/user').call('reset-counters', {'numbers': user_id})

            logger.info(f"کاربر '{username}' در User Manager v7 با موفقیت تمدید شد.")
            return True
        except Exception as e:
            logger.error(f"خطا در فرآیند تمدید کاربر '{username}' در User Manager v7: {e}")
            return False

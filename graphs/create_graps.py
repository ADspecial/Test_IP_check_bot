from typing import Optional, Dict
import os
import matplotlib.pyplot as plt

def create_user_distribution_chart(statistics: dict) -> str:
    """
    Создает столбчатую диаграмму распределения пользователей и сохраняет её в папке /data/Image_graphs.

    :param statistics: Словарь с данными о пользователях.
    :return: Путь к сохраненному изображению.
    """
    try:
        # Проверяем, существует ли папка, и создаем её, если нет
        output_dir = "./data/Image_graphs"
        os.makedirs(output_dir, exist_ok=True)

        # Извлекаем данные для диаграммы
        users = statistics.get("users", 0)
        admin_users = statistics.get("admin_users", 0)
        superadmin_users = statistics.get("superadmin_users", 0)

        # Данные для диаграммы
        categories = ['Users', 'Admins', 'Superadmins']
        values = [users, admin_users, superadmin_users]

        # Если все значения равны 0, диаграмма не имеет смысла
        if sum(values) == 0:
            raise ValueError("Нет данных для создания диаграммы.")

        # Создаем столбчатую диаграмму
        plt.figure(figsize=(8, 6))
        plt.bar(categories, values, color=['blue', 'green', 'orange'])
        plt.title('User Distribution', fontsize=16)
        plt.xlabel('Categories', fontsize=12)
        plt.ylabel('Number of Users', fontsize=12)
        plt.grid(axis='y')

        # Сохраняем изображение
        output_path = os.path.join(output_dir, "user_distribution_bar.png")
        plt.savefig(output_path)
        plt.close()

        return output_path

    except Exception as e:
        print(f"Ошибка при создании диаграммы: {e}")
        return ""

Фаззинг тестирование библиотеки MXML инструментом LibFuzzer
Шаги для выполнения работы:
0. Структура проекта

Пусть всё лежит так:

mxml-fuzzing/
  fuzz_mxml.c           # harness для LibFuzzer
  cov_runner.c          # запуск файлов для покрытия
  corpus/               # исходный и найденный корпусы
  artifacts/            # крэши/лики от LibFuzzer
  third_party/mxml/     # исходники Mini-XML

Создать папки:

mkdir -p corpus artifacts

Положить в corpus/ хотя бы оригинальный test.xml из MXML (и любые ещё валидные XML).

1. Harness для LibFuzzer

Файл fuzz_mxml.c:

// fuzz_mxml.c
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "mxml.h"          // из third_party/mxml

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;

    // делаем нуль-терминированную строку из байтов
    char *buf = (char *)malloc(Size + 1);
    if (!buf) return 0;
    memcpy(buf, Data, Size);
    buf[Size] = '\0';

    // создаём опции парсера
    mxml_options_t *options = mxmlOptionsNew();
    if (!options) {
        free(buf);
        return 0;
    }

    // пробуем распарсить строку
    mxml_node_t *root = mxmlLoadString(NULL, options, buf);

    // освобождение ресурсов – важно для LeakSanitizer
    if (root) {
        mxmlDelete(root);
    }
    mxmlOptionsDelete(options);
    free(buf);

    return 0;
}


Главные мысли, которые можно проговорить:

LibFuzzer всегда вызывает LLVMFuzzerTestOneInput.

Мы копируем вход в нуль-терминированную строку и даём её mxmlLoadString.

Всегда освобождаем root, options и буфер, чтобы не было утечек.

2. Сборка fuzz-таргета с санитайзерами

Используем clang:

cd ~/mxml-fuzzing

clang -g -O1 \
  -fsanitize=address,undefined,fuzzer \
  fuzz_mxml.c \
  third_party/mxml/mxml-attr.c \
  third_party/mxml/mxml-entity.c \
  third_party/mxml/mxml-file.c \
  third_party/mxml/mxml-get.c \
  third_party/mxml/mxml-index.c \
  third_party/mxml/mxml-node.c \
  third_party/mxml/mxml-private.c \
  third_party/mxml/mxml-search.c \
  third_party/mxml/mxml-set.c \
  -Ithird_party/mxml \
  -o fuzz_mxml


Почему перечисляем файлы руками — чтобы не тянуть testmxml.c с main().

Проверка, что всё ок:

./fuzz_mxml -runs=0 corpus

3. Краткий прогон LibFuzzer

Просто убедиться, что фаззер живой:

./fuzz_mxml -runs=1000 corpus


LibFuzzer прочитает corpus/ и 1000 раз погоняет мутации.

Если есть утечки/крэши – сразу покажет и сохранит артефакт.

4. Сохранение крэшей/утечек в отдельную папку

Создаём папку и используем -artifact_prefix:

mkdir -p artifacts

./fuzz_mxml \
  -runs=1000 \
  -artifact_prefix=./artifacts/ \
  corpus


При крэше / утечке в конце лога будет строка вида:

artifact_prefix='./artifacts/'; Test unit written to ./artifacts/leak-...


И в корне проекта ничего лишнего не валяется.

5. Длинный прогон на 2 часа

Мы хотим:

чтобы он не падал на старых leak-багов;

чтобы всё равно сохранял интересные входы в artifacts/;

чтобы был лог.

Отключаем поиск утечек: -detect_leaks=0.

./fuzz_mxml \
  -max_total_time=7200 \
  -artifact_prefix=./artifacts/ \
  -print_final_stats=1 \
  -detect_leaks=0 \
  corpus 2>&1 | tee fuzz_long.log


Что тут важно помнить, если будут вопросы:

-max_total_time=7200 — общее время в секундах (~2 часа).

-artifact_prefix — куда складывать новые интересные inputs, крэши и т.п.

-detect_leaks=0 — игнорируем лики, чтобы фаззер не останавливался.

tee fuzz_long.log — лог пишем на экран и в файл одновременно.

Если захочешь использовать многопроцессный режим:

./fuzz_mxml \
  -max_total_time=7200 \
  -artifact_prefix=./artifacts/ \
  -fork=6 -jobs=6 \
  -detect_leaks=0 \
  corpus 2>&1 | tee fuzz_long.log


Тут можно сказать: «подбираю -fork/-jobs под количество ядер, у меня 6 ядер Ryzen → 6 воркеров».

6. Быстрый просмотр справки LibFuzzer

Это можно красиво показать работодателю:

./fuzz_mxml -help=1 | less


Там видны все ключи (-max_total_time, -fork, -artifact_prefix, лимиты и т.д.).

7. Подготовка к измерению покрытия (GCOV/LCOV)

Для покрытия мы собираем отдельный бинарь без санитайзеров, но с --coverage.

Файл cov_runner.c (у тебя он уже есть, но на всякий случай):

// cov_runner.c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s file1 [file2 ...]\n", argv[0]);
        return 1;
    }

    for (int i = 1; i < argc; i++) {
        const char *path = argv[i];
        FILE *f = fopen(path, "rb");
        if (!f) {
            perror(path);
            continue;
        }

        if (fseek(f, 0, SEEK_END) != 0) {
            perror("fseek");
            fclose(f);
            continue;
        }

        long sz = ftell(f);
        if (sz < 0) {
            perror("ftell");
            fclose(f);
            continue;
        }
        rewind(f);

        uint8_t *buf = malloc((size_t)sz);
        if (!buf) {
            fprintf(stderr, "malloc failed for %s\n", path);
            fclose(f);
            continue;
        }

        size_t rd = fread(buf, 1, (size_t)sz, f);
        fclose(f);

        LLVMFuzzerTestOneInput(buf, rd);

        free(buf);
    }

    return 0;
}

8. Сборка бинаря для покрытия

Здесь уже gcc и --coverage:

gcc -g -O0 --coverage \
  cov_runner.c fuzz_mxml.c \
  third_party/mxml/mxml-attr.c \
  third_party/mxml/mxml-entity.c \
  third_party/mxml/mxml-file.c \
  third_party/mxml/mxml-get.c \
  third_party/mxml/mxml-index.c \
  third_party/mxml/mxml-node.c \
  third_party/mxml/mxml-private.c \
  third_party/mxml/mxml-search.c \
  third_party/mxml/mxml-set.c \
  -Ithird_party/mxml \
  -o mxml_cov_runner


Главное — не включать testmxml.c, иначе будет «multiple definition of main».

9. Прогон для покрытия

Теперь гоняем по всем интересным файлам: исходный корпус + то, что нашёл фаззер.

Например:

./mxml_cov_runner corpus/* artifacts/*


После этого в дереве проекта появятся .gcda файлы (данные покрытия).

10. Сбор покрытия LCOV + HTML-отчёт
10.1. Собрать сырые данные
lcov --capture --directory . --output-file coverage.info

10.2. Отфильтровать системные файлы
lcov --remove coverage.info '/usr/*' \
     --output-file coverage.filtered.info

10.3. Сгенерировать HTML
genhtml coverage.filtered.info \
  --output-directory coverage_html


Посмотреть:

xdg-open coverage_html/index.html
# или
# cd coverage_html && python3 -m http.server 5500
# и зайти в браузере на http://localhost:5500


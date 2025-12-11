Фаззинг тестирование библиотеки MXML инструментом LibFuzzer
Шаги для выполнения работы:
0. Окружение

WSL, Ubuntu 24.04, репо: ~/mxml-fuzzing, mxml лежит в third_party/mxml.

sudo apt update
sudo apt install -y build-essential clang llvm afl++ lcov

1. AFL-driver (обёртка над LLVMFuzzerTestOneInput)

Файл в корне: afl_driver.c

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

int main(void) {
    static uint8_t buf[1024 * 1024]; // до 1 МБ на вход
    size_t n = fread(buf, 1, sizeof(buf), stdin);
    if (n > 0) {
        LLVMFuzzerTestOneInput(buf, n);
    }
    return 0;
}


В fuzz_mxml.c уже реализован LLVMFuzzerTestOneInput, мы его переиспользуем.

2. Сборка mxml под AFL++ (без санитайзеров)
cd ~/mxml-fuzzing

afl-clang-fast -g -O2 \
  -Ithird_party/mxml \
  -DHAVE_CONFIG_H \
  fuzz_mxml.c \
  afl_driver.c \
  third_party/mxml/mxml-*.c \
  -o afl_mxml


Проверка, что бинарь живой:

./afl_mxml < third_party/mxml/test.xml

3. Подготовка входов и первый запуск AFL++
cd ~/mxml-fuzzing

mkdir -p afl_in afl_out
cp third_party/mxml/test.xml afl_in/seed1.xml

AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
AFL_SKIP_CPUFREQ=1 \
afl-fuzz -i afl_in -o afl_out -- ./afl_mxml


Куда смотреть в UI AFL:

overall results → corpus count, saved crashes, saved hangs

findings in depth → total crashes, total tmouts

После остановки:

ls afl_out/default
# там должны быть: crashes, hangs, queue

4. Бинарь с AddressSanitizer для поиска “настоящих” багов
cd ~/mxml-fuzzing

AFL_USE_ASAN=1 afl-clang-fast -g -O1 \
  -Ithird_party/mxml \
  -DHAVE_CONFIG_H \
  fuzz_mxml.c \
  afl_driver.c \
  third_party/mxml/mxml-*.c \
  -fsanitize=address \
  -o afl_mxml_asan


Проверка:

./afl_mxml_asan < third_party/mxml/test.xml


Запуск AFL:

mkdir -p afl_out_asan

AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
AFL_SKIP_CPUFREQ=1 \
ASAN_OPTIONS=abort_on_error=1:symbolize=0:detect_leaks=0 \
afl-fuzz -i afl_in -o afl_out_asan -- ./afl_mxml_asan

5. Бинарь с Address+LeakSanitizer (собирать утечки как крэши)
cd ~/mxml-fuzzing

AFL_USE_ASAN=1 afl-clang-fast -g -O1 \
  -Ithird_party/mxml \
  -DHAVE_CONFIG_H \
  fuzz_mxml.c \
  afl_driver.c \
  third_party/mxml/mxml-*.c \
  -fsanitize=address,leak \
  -o afl_mxml_leak


Проверка:

./afl_mxml_leak < third_party/mxml/test.xml


Фаззинг c учётом утечек:

mkdir -p afl_out_leak

AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
AFL_SKIP_CPUFREQ=1 \
ASAN_OPTIONS=abort_on_error=1:symbolize=0:detect_leaks=1 \
afl-fuzz -i afl_in -o afl_out_leak -- ./afl_mxml_leak


После работы:

ls afl_out_leak/default/crashes
# файлы id:0000... — входы, где LSan нашёл утечки


(Если надо автоперезапуск, держи мини-скрипт:)

# run_afl_leak.sh
#!/usr/bin/env bash
cd "$(dirname "$0")"

while true; do
  AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
  AFL_SKIP_CPUFREQ=1 \
  ASAN_OPTIONS=abort_on_error=1:symbolize=0:detect_leaks=1 \
  afl-fuzz -i afl_in -o afl_out_leak -- ./afl_mxml_leak
  sleep 5
done

chmod +x run_afl_leak.sh
./run_afl_leak.sh

6. Coverage для AFL++ через gcov/lcov

Идея:
АFL++ → гоняет быстрый/санитайзерный бинарь,
отдельный mxml_cov_runner → оффлайн считает покрытие по corpus’у AFL.

6.1. Сохранить отчёт LibFuzzer (если он уже был)
cd ~/mxml-fuzzing
mv coverage_html coverage_libfuzzer_html   # если такая папка есть

6.2. Собрать coverage-раннер под gcov
cd ~/mxml-fuzzing

rm -f mxml_cov_runner
find . -maxdepth 1 -name 'mxml_cov_runner-*.gcda' -delete
find . -maxdepth 1 -name 'mxml_cov_runner-*.gcno' -delete

gcc -g --coverage \
  -Ithird_party/mxml \
  -DHAVE_CONFIG_H \
  fuzz_mxml.c \
  cov_runner.c \
  third_party/mxml/mxml-*.c \
  -o mxml_cov_runner


(в cov_runner.c — main, который для каждого файла читает байты и вызывает LLVMFuzzerTestOneInput)

6.3. Собрать corpus из AFL в отдельную папку
mkdir -p coverage_afl_inputs

cp afl_out/default/queue/id:*        coverage_afl_inputs/ 2>/dev/null || true
cp afl_out_asan/default/queue/id:*   coverage_afl_inputs/ 2>/dev/null || true
cp afl_out_leak/default/queue/id:*   coverage_afl_inputs/ 2>/dev/null || true
cp afl_out_leak/default/crashes/id:* coverage_afl_inputs/ 2>/dev/null || true  # по желанию

6.4. Прогнать corpus через раннер
./mxml_cov_runner coverage_afl_inputs/*

6.5. Снять lcov и сделать HTML
# сырое покрытие
lcov --capture --directory . --output-file coverage_afl.info

# фильтруем системные файлы
lcov --remove coverage_afl.info '/usr/*' --output-file coverage_afl.filtered.info

# HTML-отчёт
rm -rf coverage_afl_html
genhtml coverage_afl.filtered.info --output-directory coverage_afl_html


В итоге в корне репо:

coverage_libfuzzer_html/ — отчёт по LibFuzzer-корпусу

coverage_afl_html/ — отчёт по AFL++-корпусу


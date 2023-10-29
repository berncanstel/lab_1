 #include <stdio.h>
 #include <libakrypt.h>


ak_uint8* read_file(const char* filename, size_t* length){
    FILE* file = fopen(filename, "rb");
    if (file == NULL) {
        printf("No such file: %s\n", filename);
        exit(1);
    }
    fseek(file, 0, SEEK_END);
    *length = ftell(file);
    rewind(file);
    ak_uint8* buffer = (ak_uint8*)malloc(*length);

    if (fread(buffer, 1, *length, file) < *length) {
        printf("Error while read file\n");
        free(buffer);
        fclose(file);
        exit(1);
    }
    fclose(file);
    return buffer;
}


void write_file(const char* filename, ak_uint8* buffer, size_t length) {
    FILE* file = fopen(filename, "wb");
    if (file == NULL) {
        printf("Cannot open file %s\n", filename);
        exit(1);
    }
    if (fwrite(buffer, 1, length, file) < length) {
        printf("Error while write file\n");
        exit(1);
    }
    fclose(file);
}


void encrypt(const char* filename_plain, const char* filename_cipher){
    size_t length;
    ak_uint8* plain_data = read_file(filename_plain, &length);

    int error = ak_error_ok;
    int exitstatus = EXIT_FAILURE;
    struct bckey ctx;
    /* константное значение ключа */
    ak_uint8 key[32] = {
        0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x27, 0x01,
        0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
        0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
        0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x38  };
    /* синхропосылка */
    ak_uint8 iv[8] = { 0x01, 0x02, 0x03, 0x04, 0x11, 0xaa, 0x4e, 0x12 };

    /* выполняем последовательный вызов двух функций:
    //создаем ключ алгоритма Магма и присваиваем ему константное значение */
    ak_bckey_create_magma( &ctx );
    ak_bckey_set_key( &ctx, key, 32);

    if(( error = ak_bckey_ofb( &ctx,
                                plain_data,
                                plain_data,
                                length,
                                iv,
                                8           
                            )) != ak_error_ok );

    write_file(filename_cipher, plain_data, length);
}


void decrypt(const char* filename_plain, const char* filename_cipher){
    encrypt(filename_plain, filename_cipher);
}


int main( void ){
    /* инициализируем библиотеку */
    if( ak_libakrypt_create( NULL ) != ak_true ) {
        ak_libakrypt_destroy();
        return EXIT_FAILURE;
    }

    encrypt("./text1.txt", "./text2.txt");
    decrypt("./text2.txt", "./text3.txt");

    /* код ошибки, возвращаемый функциями библиотеки */
    int error = ak_error_ok;
    /* статус выполнения программы */
    int exitstatus = EXIT_FAILURE;
    if( error == ak_error_ok ) exitstatus = EXIT_SUCCESS;
    ak_libakrypt_destroy();
    return exitstatus;
    return 0;
}

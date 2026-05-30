with open('status.txt', 'r') as f:
    values = [int(line.strip()) for line in f if line.strip()]

expected = [0 if i % 2 == 0 else 1 for i in range(len(values))]

print("Анализ состояния лампочки:")

if not values: 
    print("Файл пуст, анализ невозможен")
else:
    current_start = 1  
    current_state = "норм" if values[0] == expected[0] else "аномалия"

    for i in range(1, len(values)):
        
        state = "норм" if values[i] == expected[i] else "аномалия"

        
        if state != current_state:
            
            if current_start == i:
                print(f"Строка {current_start}: {current_state}")
            else:
                print(f"Строки {current_start}–{i}: {current_state}")

           
            current_start = i + 1
            current_state = state

   
    if current_start == len(values):
        print(f"{len(values)}: {current_state}")
    else:
        print(f"{current_start}–{len(values)}: {current_state}")

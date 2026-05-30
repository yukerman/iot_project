import random





status = 0
def status_generator(time, flag) -> int:
    if flag == True:
        if time % 2 == 0:
            status = 0
        else: 
            status = 1
    if flag == False:
        status = random.randint(0, 1)

        
    return status

    
start_flag = 200

with open("status.txt", "w", encoding="utf-8") as f:
    for i in range(1000):
        start_flag = start_flag - 1
        f.write(f"{status_generator(i, True if start_flag > 0 else False)}\n")

    
print("Записано 1000 значений в status.txt")












'''durationtion = 30
times = list(range(duration + 1))
normal = [status_generator(t, True) for t in times]
anomaly = [status_generator(t, False) for t in times]

fig, axes = plt.subplots(2, 1, figsize=(18, 6), sharex=True)
fig.patch.set_facecolor("black")

for ax, data, color, title in (
    (axes[0], normal, "white", "Норма (flag=True)"),
    (axes[1], anomaly, "red", "Аномалия (flag=False)"),
):
    ax.set_facecolor("black")
    ax.plot(times, data, color=color, linewidth=2.5)
    ax.set_xlim(0, duration)
    ax.set_ylim(0, 1)
    ax.set_yticks([0, 1])
    ax.set_yticklabels(["0", "1"])
    ax.yaxis.set_minor_locator(plt.NullLocator())
    ax.set_xticks(times)
    ax.set_ylabel("Статус", color="white")
    ax.set_title(title, color="white")
    ax.tick_params(colors="white", axis="x", labelsize=8)

for ax in axes:
    ax.set_xlabel("Время, с", color="white")
plt.tight_layout()
axes[0].tick_params(axis="x", labelbottom=True)
plt.show() '''

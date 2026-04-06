import matplotlib.pyplot as plt

plt.style.use('default')

severities = ['CRITICAL','HIGH','MEDIUM']
counts = [2,15,8]
colors = ['#ff004c','#ff8800','#ffee00']

fig, ax = plt.subplots(figsize=(8,6))

fig.patch.set_facecolor('white')
ax.set_facecolor('white')

wedges, texts, autotexts = ax.pie(
    counts,
    labels=severities,
    colors=colors,
    autopct='%1.1f%%',
    startangle=90,
    pctdistance=0.75,   
    labeldistance=1.1,  
    wedgeprops=dict(width=0.4, edgecolor='white')
)

for autotext in autotexts:
    autotext.set_color('black')
    autotext.set_fontsize(11)
    autotext.set_weight('bold')

for text in texts:
    text.set_color('black')
    text.set_fontsize(10)

ax.set_title(
    "Distribuzione Gravità Incidenti (SOC Triage)",
    color="black",
    fontsize=14,
    fontweight='bold'
)

plt.savefig("soc_alert_distribution_report.png", dpi=300, facecolor='white')

print("Report generato con successo")

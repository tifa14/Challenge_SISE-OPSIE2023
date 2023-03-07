import streamlit as st
import pandas as pd
import numpy as np

import sklearn
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans

from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split

import matplotlib.pyplot as plt

from io import BytesIO

import plotly.express as px
import plotly.graph_objs as go

from bokeh.plotting import figure
from bokeh.models import ColumnDataSource
from bokeh.transform import jitter

import ipaddress
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder


entete= ["date","IpS","IpD","Protocol","PortD","Regle","Acces","carteReseau","Nan","Inconnu"]
data = pd.read_table('firewall.log', sep=';', names=entete)

data["date"] = pd.to_datetime(data["date"])

# Extraction de certaines informations de la colonne "date"
data["heure"] = pd.to_datetime(data["date"]).dt.hour
data["minute"] = pd.to_datetime(data["date"]).dt.minute



def home():
    st.title("Accueil 🏠")
    st.header("Bienvenue sur la page d'accueil !")

    image= "https://www.larochellegc.com/wp-content/uploads/2020/06/Analytique-Visualisation-Donnees-Analytique-scaled-925x590-c-center.jpg"
    st.markdown(f'<p style="text-align: center;"><img src="{image}"  width="50%"></p>', unsafe_allow_html=True)
    st.header("Voici vos données :")
    st.write(data)
    
    
################################################################################################################################################################################################################################################
def page2():
    st.title("Défensive 🛡")
    
    data['Acces'] = data['Acces'].replace({'Permit': 1, 'Deny': 0})

    colonne_selectionDef = ['Acces', 'PortD']
    

    # Widgets pour sélectionner les colonnes à utiliser
    selected_columnsDef = st.multiselect("Sélectionnez les colonnes à utiliser", colonne_selectionDef)
    
    
    st.header("Données Sélectionnées : ")
    st.write(data[selected_columnsDef])
    
    if len(selected_columnsDef) > 0:
    
        X = data[selected_columnsDef]
        
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
    
       
        
        n_clusters = st.sidebar.slider("Nombre de clusters", min_value=2, max_value=10, value=3)
        kmeans = KMeans(n_clusters=n_clusters)
        
        
        data['Cluster'] = kmeans.fit_predict(X_scaled)
        
        st.header("K-means : ")
        st.write("Regroupe les événements de sécurité similaires en groupes. Pour identifier les tendances nos logs du Firewall")
        figScatterK = px.scatter(data, y='PortD',x='Acces',color='Cluster', hover_data=data.columns)
        st.plotly_chart(figScatterK)
    else :
        st.warning("Veuillez sélectionner au moins une colonne.")
    
    
    
    ######################################################

    st.header("Régression : ")
    st.write("Analyse les relations entre les variables sélectionées, pour identifier les facteurs qui contribuent aux attaques et aux incidents de sécurité.")
    
    colonne_selectionDef2 = ['PortD', 'Protocol', 'Regle', 'heure']
    selected_columnsDef2 = st.multiselect("Sélectionnez les colonnes à utiliser", colonne_selectionDef2)
    
    if len(selected_columnsDef2) > 0:
    
        Xdata = pd.get_dummies(data[selected_columnsDef2])
        
        ydata = data['Acces'].replace({'Permit': 1, 'Deny': 0})
        st.header("Données Sélectionnées : ")
        st.write(Xdata)
        
        testsize = st.sidebar.slider("% test", min_value=10, max_value=90, value=20)
        X_train, X_test, y_train, y_test = train_test_split(Xdata, ydata, test_size=testsize*0.01)
        model = LogisticRegression()
        model.fit(X_train, y_train)
        #y_pred = model.predict(X_test)
    
        st.write("Coefficients de la régression :")
    
        st.table(pd.DataFrame(model.coef_, columns=Xdata.columns))
        
        
        # Créer une matrice de corrélation
        datacor = data[["date","heure","Protocol","PortD","Regle","Acces"]]
        corr = datacor.corr()
        
        # Créer une figure avec Plotly
        figcor = go.Figure(data=go.Heatmap(
                           z=corr.values,
                           x=corr.index.values,
                           y=corr.columns.values))
        
        # Ajouter des annotations à la matrice de corrélation
        for i in range(len(corr.index)):
            for j in range(len(corr.columns)):
                figcor.add_annotation(
                    x=corr.index[i],
                    y=corr.columns[j],
                    text=str(round(corr.values[i][j], 2)),
                    showarrow=False,
                    font=dict(size=12),
                    xref='x1',
                    yref='y1'
                )
        
        # Modifier les propriétés de la figure
        figcor.update_layout(
            title='Matrice de corrélation',
            xaxis_nticks=len(corr.index),
            yaxis_nticks=len(corr.columns),
            height=500,
            width=500,
            autosize=False
        )
        
        # Afficher la figure dans Streamlit
        st.plotly_chart(figcor)
    else :
        st.warning("Veuillez sélectionner au moins une colonne.")
        

################################################################################################################################################################################################################################################
def page3():
    st.title("Offensive ⚔")
    
    st.write("Cette partie permet de se mettre à la place de l'attaquant en utilisant uniquement les données à sa dispositon pour construire un modèle prédictif permettant de décider si une requête va être acceptée ou non")

    le_protocol = LabelEncoder()
    
    # Convertir les adresses IP en nombres
    data['IpS'] = data['IpS'].apply(lambda x: int(ipaddress.ip_address(x)))
    data['IpD'] = data['IpD'].apply(lambda x: int(ipaddress.ip_address(x)))
    
    data['Protocol'] = le_protocol.fit_transform(data['Protocol'])
    
    colonne_selection = ["IpS","IpD","Protocol","PortD", "heure", "minute"]

    # Widgets pour sélectionner les colonnes à utiliser
    selected_columns = st.multiselect("Sélectionnez les colonnes à utiliser", colonne_selection)
    
    # Sélection des colonnes choisies
    Xdf = data[selected_columns]
    
    ydf = data["Acces"]
    

    st.header("Données Sélectionnées : ")
    st.write(Xdf)
    
    
    if len(selected_columns) > 0:
        
        # Normalisation des variables
        scaler = StandardScaler()
        Xdf = scaler.fit_transform(Xdf)
        
        # Fractionnement des données en ensembles d'entraînement et de test
        Xdf_train, Xdf_test, ydf_train, ydf_test = train_test_split(Xdf, ydf, test_size=0.3)
        
        
        st.header("Random Forest : ")
        
        # Entraînement du modèle Random Forest
        rf = RandomForestClassifier(n_estimators=100)
        rf.fit(Xdf_train, ydf_train)
        
        # Évaluation du modèle sur l'ensemble de test
        score = rf.score(Xdf_test, ydf_test)
        st.write("Précision du modèle :", score)
        
        ### Matrice Corr
        # Créer une matrice de corrélation
        datacor2 = data[["IpS","IpD","Protocol","PortD", "heure", "minute"]]
        corr2 = datacor2.corr()
        
        # Créer une figure avec Plotly
        figcor2 = go.Figure(data=go.Heatmap(
                           z=corr2.values,
                           x=corr2.index.values,
                           y=corr2.columns.values))
        
        # Ajouter des annotations à la matrice de corrélation
        for i in range(len(corr2.index)):
            for j in range(len(corr2.columns)):
                figcor2.add_annotation(
                    x=corr2.index[i],
                    y=corr2.columns[j],
                    text=str(round(corr2.values[i][j], 2)),
                    showarrow=False,
                    font=dict(size=12),
                    xref='x1',
                    yref='y1'
                )

        
        # Modifier les propriétés de la figure
        figcor2.update_layout(
            title='Matrice de corrélation',
            xaxis_nticks=len(corr2.index),
            yaxis_nticks=len(corr2.columns),
            height=500,
            width=500,
            autosize=False
        )
        
        # Afficher la figure dans Streamlit
        st.plotly_chart(figcor2)
        
        
    else :
        st.warning("Veuillez sélectionner au moins une colonne.")
    
    st.header("Données Cible : ")
    st.write(ydf)

    
    
    
    
    


################################################################################################################################################################################################################################################
def page1():
    st.title("Visualisation 📺")

    
    df = data
    
#####connexion par protocole accepté et rejeté
    # Filtrer données par protocole
    protocols = ['TCP', 'UDP']
    df_filtered = df[df['Protocol'].isin(protocols)]

    # Filter data by port range according to RFC 6056
    df_filtered = df_filtered[df_filtered['PortD'].between(49152, 65535)]

    # compté les accepté et rejeté
    counts = df_filtered.groupby(['Protocol', 'Acces']).size().unstack(fill_value=0)

    #cré l'histogramme
    fig, ax = plt.subplots()
    counts.plot(kind='bar', stacked=True, ax=ax)

    ax.set_xlabel('Protocole')
    ax.set_ylabel('nombre de connections')
    ax.set_title('connexion par protocole accepté et rejeté')

    # plot Streamlit
    st.pyplot(fig)

    #### Filtrage par plages de ports selon la RFC 6056
    ports = range(49152, 65536) # Plage de ports selon la RFC 6056
    df_ports = df[(df.PortD.isin(ports))]

    # Top 5 des adresses IP sources et destinations les plus actives
    top_ips = pd.concat([df_ports["IpS"], df_ports["IpD"]]).value_counts().nlargest(5)
    fig1, ax1 = plt.subplots()
    ax1.bar(top_ips.index, top_ips.values)
    ax1.set_ylabel("Nombre de flux")
    ax1.set_title("Top 5 des adresses IP les plus actives")

    st.pyplot(fig1)

    #####camembert des flux par protocoles
    df_tcp = df[df["Protocol"]=="TCP"]
    df_udp = df[df["Protocol"]=="UDP"]
    tcp_count = df_tcp.shape[0]
    udp_count = df_udp.shape[0]
    total_count = df.shape[0]
    tcp_pct = tcp_count/total_count*100
    udp_pct = udp_count/total_count*100

    # camenbert
    labels = ["TCP", "UDP"]
    sizes = [tcp_pct, udp_pct]
    colors = ["lightblue", "lightgreen"]
    explode = (0.1, 0)

    fig2, ax2 = plt.subplots()
    ax2.pie(sizes, explode=explode, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90)
    ax2.axis('equal')
    ax2.set_title("Répartition des flux par protocole")

    # Affichage avec Streamlit
    st.pyplot(fig2)

    ##### histograme des flux par plages de ports selon la RFC 6056
    df_ports = df[df["PortD"].between(49152, 65535)]
    tcp_ports_count = df_ports[df_ports["Protocol"]=="TCP"].shape[0]
    udp_ports_count = df_ports[df_ports["Protocol"]=="UDP"].shape[0]
    total_ports_count = df_ports.shape[0]
    tcp_ports_pct = tcp_ports_count/total_ports_count*100
    udp_ports_pct = udp_ports_count/total_ports_count*100


    ######## histogramme de l'accès autorisé ou rejeté en fonction de la règle
    df_regle = df.groupby(["Regle", "Acces"]).size().reset_index(name="Count")
    
    # histograme
    fig4, ax4 = plt.subplots()
    df_regle_pivot = df_regle.pivot(index="Regle", columns="Acces", values="Count")
    df_regle_pivot.plot(kind="bar", stacked=True, color=["lightgreen", "red"], ax=ax4)
    
    ax4.set_title("Répartition des accès autorisés/rejetés en fonction de la règle")
    ax4.set_xlabel("Règle")
    ax4.set_ylabel("Nombre d'accès")
    
    # Affichage avec Streamlit
    st.pyplot(fig4)

    
    ##### histograme des flux par plages de ports selon la RFC 6056
    df_ports = df[df["PortD"].between(49152, 65535)]
    tcp_ports_count = df_ports[df_ports["Protocol"]=="TCP"].shape[0]
    udp_ports_count = df_ports[df_ports["Protocol"]=="UDP"].shape[0]
    total_ports_count = df_ports.shape[0]
    tcp_ports_pct = tcp_ports_count/total_ports_count*100
    udp_ports_pct = udp_ports_count/total_ports_count*100
    
    # histograme
    labels = ["TCP", "UDP"]
    sizes = [tcp_ports_pct, udp_ports_pct]
    colors = ["lightblue", "lightgreen"]
    
    fig5, ax5 = plt.subplots()
    patches, _ = ax5.bar(labels, sizes, color=colors)
    
    # Affichage avec Streamlit
    ax5.set_title("Répartition des flux par plage de ports")
    st.pyplot(fig5)

    ##### Histogramme de la répartition des flux rejetés et autorisés en fonction du port de destination
    df_rejet = df[df["Acces"] == "Deny"]
    df_autorise = df[df["Acces"] == "Permit"]
    
    #histogramme
    fig6, ax6 = plt.subplots()
    ax6.hist([df_rejet["PortD"], df_autorise["PortD"]], bins=50, stacked=True, color=["red", "lightgreen"], label=["Flux rejetés", "Flux autorisés"])
    
    ax6.set_xlabel("Port de destination")
    ax6.set_ylabel("Nombre de flux")
    ax6.set_title("Répartition des flux rejetés et autorisés en fonction du port de destination")
    
    # Affichage avec Streamlit
    st.pyplot(fig6)


    ######### Répartition des flux autorisés et rejetés en fonction du protocole (flux = echange de donnée calculé grace a IPS et IPD)
    # On filtre les flux rejetés et autorisés
    df_rejet = df[df["Acces"] == "Deny"]
    df_autorise = df[df["Acces"] == "Permit"]
    
    # flux pour chaque protocole
    count_rejet = df_rejet["Protocol"].value_counts()
    count_autorise = df_autorise["Protocol"].value_counts()
    
    # noms des protocoles
    protocoles = list(set(df["Protocol"].tolist()))
    
    # histogramme
    fig7, ax7 = plt.subplots()
    bar_width = 0.35
    ax7.bar(protocoles, count_rejet, bar_width, color="red", label="Flux rejetés")
    ax7.bar(protocoles, count_autorise, bar_width, bottom=count_rejet, color="lightgreen", label="Flux autorisés")
    
    ax7.set_xlabel("Protocole")
    ax7.set_ylabel("Nombre de flux")
    ax7.set_title("Répartition des flux autorisés et rejetés en fonction du protocole")
    ax7.legend()
    
    # Affichage avec Streamlit
    st.pyplot(fig7)    
    
    
    
    df_autorise = data[data['Acces'] == 'Permit']
    counts = df_autorise['PortD'].value_counts()
    top_10 = counts[:10]
    
    fig, ax = plt.subplots(figsize=(8, 8))
    ax.pie(top_10.values, labels=top_10.index, autopct='%1.1f%%')
    ax.set_title('Top 10 Ports Autorisés')
    
    # On convertit le graphique en une image à afficher avec Streamlit
    img = BytesIO()
    fig.savefig(img, format='png')
    st.image(img.getvalue(), use_column_width=True)
    
    
    ################## BOKEH
    
    # On filtre les flux autorisés
    df_autorise = df[df["Acces"] == "Permit"]
    
    # On crée une source de données pour Bokeh
    source = ColumnDataSource(df_autorise)
    
    # On crée le graphique
    p = figure(title="Répartition des ports source des flux autorisés", tools="", background_fill_color="#fafafa")
    p.yaxis.axis_label = "Ports source"
    p.xaxis.axis_label = "Nombre de flux"
    p.axis.axis_line_color = None
    
    # On ajoute les burtins
    p.circle(x='PortD', y=jitter('index', width=0.6, range=p.y_range), size=4, alpha=0.6, source=source)
    
    # On affiche le graphique avec Streamlit
    st.bokeh_chart(p, use_container_width=True)
    
    
        
    
    
    
    
    
    
    
##################################### MENU ################################################################################################################################################
# Créer une liste des pages
pages = {
    "Accueil 🏠": home,
    "Visualisation 📺": page1,
    "Défensive 🛡": page2,
    "Offensive ⚔": page3
}

# Ajouter une barre de navigation pour naviguer entre les pages
st.sidebar.title("Menu 📊")
selection = st.sidebar.radio("Aller à", list(pages.keys()))

# Exécuter la fonction de la page sélectionnée
page = pages[selection]
page()
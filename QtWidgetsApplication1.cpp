#include "QtWidgetsApplication1.h"
#include <QWidget>
#include <QLabel>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QTextEdit>
#include <QPushButton>
#include <QComboBox>
#include <QGroupBox> 
#include <QJsonObject>
#include <QJsonDocument>
#include <QCryptographicHash>
#include <QByteArray>
#include <QChildEvent>
#include <QLineEdit>
#include "C:\Users\pc\OneDrive\Desktop\cryptopp\base64.h"
#include "C:\Users\pc\OneDrive\Desktop\cryptopp\hmac.h"
#include <C:\Users\pc\OneDrive\Desktop\cryptopp\sha.h>
#include <QMessageAuthenticationCode>
#include <QMessageBox>
#include <QDebug>

using namespace CryptoPP;
QLabel* signatureTextLabel;

QtWidgetsApplication1::QtWidgetsApplication1(QWidget* parent)
    : QMainWindow(parent)
{
    ui.setupUi(this);
       // background de la fenetre 
        this->setStyleSheet("background-color: black;");
        //longeur et largeur de fenetre 
        this->resize(1000, 600); 
        // Création des zones pour afficher le token, header, payload et signature
      
        QWidget* centralWidget = new QWidget(this);    //allocation de memoire denamique d'un objet de Qwidget
        QVBoxLayout* mainLayout = new QVBoxLayout(centralWidget);

        // Deux layouts horizontaux pour les rectangles en haut de la fenêtre
        QHBoxLayout* topLayout1 = new QHBoxLayout;
        QHBoxLayout* topLayout2 = new QHBoxLayout;

        //////////////////////////////////////////////////////ALGO///////////////////////////////////////////////////////////////
        // Deuxieme rectangle horizontal pour choisir d'algorithme

        QLabel* algoLabel = new QLabel("Algorithme");
        algoLabel->setStyleSheet("color: white; font-family: Bahnschrift SemiBold ;font-size: 15px;");

        QComboBox* liste = new QComboBox(this);

        //

        liste->setObjectName("liste"); 
        liste->setStyleSheet("color: black; background-color: white;");
        liste->addItem("HS256");
        liste->addItem("HS384");

        //syntaxe: connect( senderObject, &SenderClass::signalName, receiverObject, &ReceiverClass::slotName);

        connect(liste, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &QtWidgetsApplication1::updateHeaderAlg);

        // Connecter currentIndexChanged signal a la fct  generateToken 
        connect(liste, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &QtWidgetsApplication1::generateToken);

        QHBoxLayout* comboLayout = new QHBoxLayout;

        comboLayout->addWidget(algoLabel);
        comboLayout->addWidget(liste);
        topLayout2->addLayout(comboLayout);
        topLayout2->setContentsMargins(0, 0, 0, 10);
        topLayout2->setSpacing(40);
        topLayout2->setAlignment(Qt::AlignHCenter);

        mainLayout->addLayout(topLayout1);
        mainLayout->addLayout(topLayout2);



        // Layout pour les composants à gauche (header, payload, signature)
        QVBoxLayout* leftComponentsLayout = new QVBoxLayout;

        /// /////////////////////////////////////////ENCODED///////////////////////////////////////////////////////////////////

        QLabel* encodedLabel = new QLabel("DECODED");
        encodedLabel->setStyleSheet("color: white; font-family: Bahnschrift SemiBold ;font-size: 30px;");
        leftComponentsLayout->addWidget(encodedLabel);


        ////////////////////////////////////////////////////HEADER//////////////////////////////////////////////////////////////////
        QGroupBox* headerGroupBox = new QGroupBox("Header");
        headerGroupBox->setStyleSheet("color: white; border: 1px solid #235e36; background-color:#235e36; border-radius:15px; font-family: Bahnschrift SemiBold ;font-size: 18px;qproperty-alignment: AlignCenter;");
        QVBoxLayout* headerGroupLayout = new QVBoxLayout;
        headerGroupBox->setFixedWidth(430);
        headerGroupBox->setFixedHeight(130);

        QTextEdit* headerTextEdit = new QTextEdit("");
        //initialisation de header par des valeurs par defaut 
        QString initialHeader = "{\"alg\": \"HS256\", \"typ\": \"JwT\"}"; 
        headerTextEdit->setPlainText(initialHeader);
        headerTextEdit->setObjectName("headerTextEdit"); //on fait object name pour le retrouver 
        QString headerStyleSheet = "QTextEdit { background-color: white; color: red; border-radius: 15px; }";
        headerTextEdit->setStyleSheet(headerStyleSheet);
        headerTextEdit->setFixedWidth(400);
        headerTextEdit->setFixedHeight(100);

        //tout modification dans header fait un changement dans la signature  du token 
        connect(headerTextEdit, &QTextEdit::textChanged, this, &QtWidgetsApplication1::generateToken);

        headerGroupLayout->addWidget(headerTextEdit);
        headerGroupBox->setLayout(headerGroupLayout);

      
        /// //////////////////////////////////////PAYLOAD///////////////////////////////////////////////////////////////////////////////
        QGroupBox* payloadGroupBox = new QGroupBox("Payload");
        payloadGroupBox->setStyleSheet("color: white; border: 1px solid #235e36;background-color:#235e36; border-radius:15px; font-family: Bahnschrift SemiBold ;font-size: 18px;qproperty-alignment: AlignCenter;");
        QVBoxLayout* payloadGroupLayout = new QVBoxLayout;
        payloadGroupBox->setFixedWidth(430);
        payloadGroupBox->setFixedHeight(178);

        QTextEdit* payloadTextEdit = new QTextEdit("");


        payloadTextEdit->setObjectName("payloadTextEdit");

        // initialisation de payload par des valeurs par defaut 
        QString payload = "{\n"
            "  \"sub\": \"1234567890\",\n"
            "  \"name\": \"John Doe\",\n"
            "  \"iat\": 1516239022\n"
            "}";
        payloadTextEdit->setPlainText(payload);

        QString payloadStyleSheet = "QTextEdit { background-color: white; color: purple; border-radius: 15px; }";
        payloadTextEdit->setStyleSheet(payloadStyleSheet);
        payloadTextEdit->setFixedWidth(400);
        payloadTextEdit->setFixedHeight(145);

        //tout modification dans payload fait un changement dans la signature  du token 
        connect(payloadTextEdit, &QTextEdit::textChanged, this, &QtWidgetsApplication1::generateToken);

        payloadGroupLayout->addWidget(payloadTextEdit);
        payloadGroupBox->setLayout(payloadGroupLayout);



        ///////////////////////////////////////////////////////////SIGNATURE/////////////////////////////////////////////////////
        QGroupBox* signatureGroupBox = new QGroupBox("Signature");
        signatureGroupBox->setStyleSheet("color: white; border: 1px solid #235e36; background-color: #235e36; border-radius: 15px; font-family: Bahnschrift SemiBold; font-size: 18px; qproperty-alignment: AlignCenter;");
        signatureGroupBox->setFixedWidth(430);
        signatureGroupBox->setFixedHeight(178);

     

        QVBoxLayout* signatureGroupLayout = new QVBoxLayout;

        // QGroupBox pour les éléments à l'intérieur du QGroupBox principal
        QGroupBox* innerGroupBox = new QGroupBox();
        innerGroupBox->setStyleSheet("background-color: white;"); // Fond blanc
        QVBoxLayout* innerGroupLayout = new QVBoxLayout;
        innerGroupBox->setFixedWidth(400);
        innerGroupBox->setFixedHeight(148);
        //initialisation de signature par valeur pr defaut 
        QString labelText = "HMACSHA256(\n  base64UrlEncode(header) + \".\" +\n  base64UrlEncode(payload), ";

        QLabel* signatureTextLabel = new QLabel(labelText);
        signatureTextLabel->setStyleSheet("color: blue; qproperty-alignment: AlignLeft;border: 1px solid white");
        signatureTextLabel->setFixedWidth(350);
        signatureTextLabel->setFixedHeight(70);
        signatureTextLabel->setObjectName("signatureTextLabel");
        QHBoxLayout* secretKeyLayout = new QHBoxLayout;

        QTextEdit* CleSecre = new QTextEdit("votre_cle_secrete");

        CleSecre->setStyleSheet("color: blue;qproperty-alignment: AlignLeft; border: 1px solid #235e36;");
        secretKeyLayout->addWidget(CleSecre);
        CleSecre->setObjectName("CleSecre");
        //tout modification dans la signature fait un changement dans le  token 
        connect(CleSecre, &QTextEdit::textChanged, this, &QtWidgetsApplication1::generateToken);


        innerGroupLayout->addWidget(signatureTextLabel);
        innerGroupLayout->addLayout(secretKeyLayout);

        innerGroupBox->setLayout(innerGroupLayout);

        signatureGroupLayout->addWidget(innerGroupBox);
        signatureGroupBox->setLayout(signatureGroupLayout);

        leftComponentsLayout->addWidget(headerGroupBox);
        leftComponentsLayout->addWidget(payloadGroupBox);
        leftComponentsLayout->addWidget(signatureGroupBox);
        leftComponentsLayout->setContentsMargins(0, 0, 0, 0);


        /// ///////////////////////////////////////////////////DECODED///////////////////////////////////////////////
        QVBoxLayout* rightLayout = new QVBoxLayout;
        errorMessageLabel = new QLabel("");
        errorMessageLabel->setStyleSheet("color: red; font-weight: bold;font-size: 17px;");
        errorMessageLabel->setAlignment(Qt::AlignHCenter);  

        QLabel* encodedTokenLabel = new QLabel("ENCODED");
        encodedTokenLabel->setStyleSheet("color: white; font-family: Bahnschrift SemiBold ;font-size: 30px;");
       
        
        rightLayout->addWidget(encodedTokenLabel);
        rightLayout->addWidget(errorMessageLabel);

        /////////////////////////////////////////////////////////TOKEN///////////////////////////////////////////////////////////
        QGroupBox* tokenGroupBox = new QGroupBox("Token");
        tokenGroupBox->setStyleSheet("color: white;border: 1px solid #235e36;background-color:#235e36; border-radius:15px; font-family: Bahnschrift SemiBold ;font-size: 18px;qproperty-alignment: AlignCenter;margin-bottom: 10px ");
        tokenGroupBox->setFixedWidth(520);
        tokenGroupBox->setFixedHeight(498);

        // Création du QTextEdit pour le token
        QTextEdit* tokenTextEdit = new QTextEdit("");
        tokenTextEdit->setObjectName("tokenTextEdit"); // Nommage de l'objet ici pour le retrouver
        tokenTextEdit->setMaximumSize(500, 450);
        QString tokenStyleSheet = "QTextEdit { background-color: white; color: black; border-radius: 15px;}";
        tokenTextEdit->setStyleSheet(tokenStyleSheet);

        // Ajout du QTextEdit au layout du groupbox
        QVBoxLayout* tokenLayout = new QVBoxLayout;
        tokenLayout->addWidget(tokenTextEdit);
        tokenGroupBox->setLayout(tokenLayout);
       
        // Ajout du groupbox à votre layout principal (rightLayout dans votre cas)
        rightLayout->addWidget(tokenGroupBox);

    

        QHBoxLayout* bottomLayout = new QHBoxLayout;
        bottomLayout->addLayout(leftComponentsLayout);
        bottomLayout->addLayout(rightLayout);
        mainLayout->addLayout(bottomLayout);
        centralWidget->setLayout(mainLayout);
        this->setCentralWidget(centralWidget);
    }

    QtWidgetsApplication1::~QtWidgetsApplication1() {}

    void QtWidgetsApplication1::updatePayload(QString sub, QString name, QString iat, QString admin) {
        QTextEdit* payloadTextEdit = findChild<QTextEdit*>("payloadTextEdit");
        if (payloadTextEdit) {
            //declation de structure json
            QJsonObject payloadObject;
            //inisialisation de cles de json 
            // ajout de data communes dans le payload 
            payloadObject["sub"] = sub;
            payloadObject["name"] = name;
            payloadObject["iat"] = iat;

            // ajout de donnees specifiques selon l'algorithme selectione
            if (!admin.isEmpty()) {
                payloadObject["admin"] = (admin == "true") ? true : false;
            }
            //conversion en format json document 
            QJsonDocument doc(payloadObject);
            //conversion en formatted json format
            QString payloadString = doc.toJson();
            //affichage du resulat dans payloadttextedit 
            payloadTextEdit->setPlainText(payloadString);
        }
    }

    // cette fct sert a changer l'algorithm dans la signature selon algorithm selectione
    void QtWidgetsApplication1::updateSignature(QString algorithm, QString secretKey) {
        QLabel* signatureTextLabel = findChild<QLabel*>("signatureTextLabel");
        if (signatureTextLabel) {
            QString signature = QString("%1(\n  base64UrlEncode(header) + \".\" +\n  base64UrlEncode(payload),\n  %2\n)").arg(algorithm, secretKey);
            signatureTextLabel->setText(signature);
        }
    }
    //cette fct sert a changer l'algorithme dans header et signature selon celui qui est selectionne
    void QtWidgetsApplication1::updateHeaderAlg(int index) {
        QString algorithm;
        QString type = "JWT"; // Assuming the default type is JWT
        QString sub, name, iat, admin;
        // Determine the algorithm based on the selected index
        switch (index) {
        case 0:
            algorithm = "HS256";
            sub = "1234567890";
            name = "John Doe";
            iat = "1516239022";
            break;
        case 1:
            algorithm = "HS384";
            sub = "1234567890";
            name = "John Doe";
            iat = "1516239022";
            admin = "true";
            break;
        default:
            algorithm = "HS256";
            sub = "1234567890";
            name = "John Doe";
            iat = "1516239022";
            break;
        }

        QTextEdit* headerTextEdit = findChild<QTextEdit*>("headerTextEdit");
        if (headerTextEdit) {
            //on place contenu de header dans currenttext 
            QString currentText = headerTextEdit->toPlainText();
            QString newText = currentText.replace(QRegularExpression("\"alg\"\\s*:\\s*\"\\w+\""),
                QString("\"alg\": \"%1\"").arg(algorithm));
            newText = newText.replace(QRegularExpression("\"typ\"\\s*:\\s*\"\\w+\""),
                QString("\"typ\": \"%1\"").arg(type));
            headerTextEdit->setPlainText(newText);

            qDebug() << "Algorithm selectione:" << algorithm;
            qDebug() << "avant mise a jour du payload - Sub:" << sub << " Name:" << name << " IAT:" << iat;

            updatePayload(sub, name, iat, admin);

            qDebug() << "apres mise a jour du payload - Sub:" << sub << " Name:" << name << " IAT:" << iat;
        }

        QString signatureText;
        switch (index) {
        case 0:
            signatureText = "HMACSHA256(\n  base64UrlEncode(header) + \".\" +\n  base64UrlEncode(payload),\n  your-256-bit-secret\n)";
            break;
        case 1:
            signatureText = "HMACSHA384(\n  base64UrlEncode(header) + \".\" +\n  base64UrlEncode(payload),\n  your--bit-secret\n)";
            break;
        default:
            signatureText = "HMACSHA256(\n  base64UrlEncode(header) + \".\" +\n  base64UrlEncode(payload),\n  your-256-bit-secret\n)";
            break;
        }

        QLabel* signatureTextLabel = findChild<QLabel*>("signatureTextLabel");
        if (signatureTextLabel) {
            signatureTextLabel->setText(signatureText);
        }
    }
    //cette fct sert a remplacer les symboles + et / et = dans token par autres signifiants 
    QString QtWidgetsApplication1::cleanToken(const QString & token) {
        QString cleanedToken = token;
        cleanedToken.replace("+", "-");
        cleanedToken.replace("/", "_");
        cleanedToken.replace("=", "");
        return cleanedToken;
    }
    //cette fct sert a faire la generation du token 
    void QtWidgetsApplication1::generateToken() {
        QString jwtToken;
        byte digest[CryptoPP::HMAC<CryptoPP::SHA256>::DIGESTSIZE];

        // Retrieve text fields
        QTextEdit* headerTextEdit = findChild<QTextEdit*>("headerTextEdit");
        QTextEdit* payloadTextEdit = findChild<QTextEdit*>("payloadTextEdit");
        QTextEdit* tokenTextEdit = findChild<QTextEdit*>("tokenTextEdit");
        QTextEdit* CleSecre = findChild<QTextEdit*>("CleSecre");
        QComboBox* liste = findChild<QComboBox*>("liste");

        if (!liste || !CleSecre || !headerTextEdit || !payloadTextEdit || !tokenTextEdit || !errorMessageLabel) {
            errorMessageLabel->setText("Error: champs introuvables");
            return;
        }

        QString selectedAlgorithm = liste->currentText();
        QString secretText = CleSecre->toPlainText();

        if (secretText.isEmpty()) {
            errorMessageLabel->setText("Error: CleSecre est vide");
            return;
        }

        QByteArray secretKey = secretText.toUtf8();

        // s'assurer qu la longeur du cle est 32 bites s'il est necessaire
        if (secretKey.size() < 32) {
            secretKey = secretKey.leftJustified(32, '\0');
        }

        QString headerText = headerTextEdit->toPlainText();
        QString payloadText = payloadTextEdit->toPlainText();

        QJsonDocument headerJson = QJsonDocument::fromJson(headerText.toUtf8());
        QJsonDocument payloadJson = QJsonDocument::fromJson(payloadText.toUtf8());

        if (!headerJson.isNull() && !payloadJson.isNull()) {
            QString encodedHeader = QString::fromUtf8(headerJson.toJson().toBase64());
            QString encodedPayload = QString::fromUtf8(payloadJson.toJson().toBase64());

            QString dataToSign = encodedHeader + "." + encodedPayload;

            if (selectedAlgorithm == "HS256") {
                byte digest[CryptoPP::HMAC<CryptoPP::SHA256>::DIGESTSIZE];
                // Generation de  HMAC-SHA256 signature
                CryptoPP::HMAC<CryptoPP::SHA256> hmac256((const byte*)secretKey.data(), secretKey.size());
                hmac256.CalculateDigest(digest, reinterpret_cast<const byte*>(dataToSign.toUtf8().constData()), dataToSign.length());
                QByteArray signatureBytes(reinterpret_cast<const char*>(digest), CryptoPP::HMAC<CryptoPP::SHA256>::DIGESTSIZE);
                QString signatureBase64 = signatureBytes.toBase64();
                jwtToken = dataToSign + "." + signatureBase64;
            }
            else if (selectedAlgorithm == "HS384") {
                byte digest384[CryptoPP::HMAC<CryptoPP::SHA384>::DIGESTSIZE];
                CryptoPP::HMAC<CryptoPP::SHA384> hmac384((const byte*)secretKey.data(), secretKey.size());
                hmac384.CalculateDigest(digest384, reinterpret_cast<const byte*>(dataToSign.toUtf8().constData()), dataToSign.length());

                // utilisation de  SHA384 signature pour le reste du process si HS384 est selectionee
                QByteArray signatureBytes384(reinterpret_cast<const char*>(digest384), CryptoPP::HMAC<CryptoPP::SHA384>::DIGESTSIZE);
                QString signatureBase64_384 = signatureBytes384.toBase64();
                jwtToken = dataToSign + "." + signatureBase64_384;
                qDebug() << "Encoded Signature (HS384):" << signatureBase64_384;
            }
            else {
                errorMessageLabel->setText("Error: Algorithme insupportable");


                return;
            }

            QString cleanedJwtToken = cleanToken(jwtToken);

            QString coloredToken = "<font color='red'>" + cleanedJwtToken.section('.', 0, 0) + "</font>.<font color='purple'>" +
                cleanedJwtToken.section('.', 1, 1) + "</font>.<font color='blue'>" +
                cleanedJwtToken.section('.', 2, 2) + "</font>";
            tokenTextEdit->setHtml(coloredToken);
        }
        else {
            errorMessageLabel->setText("Error dans la conversion de json");
        }
    }

   

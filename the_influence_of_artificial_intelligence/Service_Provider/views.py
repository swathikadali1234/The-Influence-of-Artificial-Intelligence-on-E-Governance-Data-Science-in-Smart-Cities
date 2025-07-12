
from django.db.models import  Count, Avg
from django.shortcuts import render, redirect
from django.db.models import Count
from django.db.models import Q
import datetime
import xlwt
from django.http import HttpResponse


import pandas as pd
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
from sklearn.metrics import accuracy_score
from sklearn.tree import DecisionTreeClassifier

# Create your views here.
from Remote_User.models import ClientRegister_Model,cyber_attack_detection,detection_ratio,detection_accuracy


def serviceproviderlogin(request):
    if request.method  == "POST":
        admin = request.POST.get('username')
        password = request.POST.get('password')
        if admin == "Admin" and password =="Admin":
            detection_accuracy.objects.all().delete()
            return redirect('View_Remote_Users')

    return render(request,'SProvider/serviceproviderlogin.html')

def View_Prediction_Of_Cyber_Attack_Type_Ratio(request):
    detection_ratio.objects.all().delete()
    ratio = ""
    kword = 'DDoS'
    print(kword)
    obj = cyber_attack_detection.objects.all().filter(Q(Prediction=kword))
    obj1 = cyber_attack_detection.objects.all()
    count = obj.count();
    count1 = obj1.count();
    ratio = (count / count1) * 100
    if ratio != 0:
        detection_ratio.objects.create(names=kword, ratio=ratio)

    ratio12 = ""
    kword12 = 'Intrusion'
    print(kword12)
    obj12 = cyber_attack_detection.objects.all().filter(Q(Prediction=kword12))
    obj112 = cyber_attack_detection.objects.all()
    count12 = obj12.count();
    count112 = obj112.count();
    ratio12 = (count12 / count112) * 100
    if ratio12 != 0:
        detection_ratio.objects.create(names=kword12, ratio=ratio12)

    ratio12 = ""
    kword12 = 'Malware'
    print(kword12)
    obj12 = cyber_attack_detection.objects.all().filter(Q(Prediction=kword12))
    obj112 = cyber_attack_detection.objects.all()
    count12 = obj12.count();
    count112 = obj112.count();
    ratio12 = (count12 / count112) * 100
    if ratio12 != 0:
        detection_ratio.objects.create(names=kword12, ratio=ratio12)

    obj = detection_ratio.objects.all()
    return render(request, 'SProvider/View_Prediction_Of_Cyber_Attack_Type_Ratio.html', {'objs': obj})

def View_Remote_Users(request):
    obj=ClientRegister_Model.objects.all()
    return render(request,'SProvider/View_Remote_Users.html',{'objects':obj})

def charts(request,chart_type):
    chart1 = detection_ratio.objects.values('names').annotate(dcount=Avg('ratio'))
    return render(request,"SProvider/charts.html", {'form':chart1, 'chart_type':chart_type})

def charts1(request,chart_type):
    chart1 = detection_accuracy.objects.values('names').annotate(dcount=Avg('ratio'))
    return render(request,"SProvider/charts1.html", {'form':chart1, 'chart_type':chart_type})

def View_Prediction_Of_Cyber_Attack_Type(request):
    obj =cyber_attack_detection.objects.all()
    return render(request, 'SProvider/View_Prediction_Of_Cyber_Attack_Type.html', {'list_objects': obj})

def likeschart(request,like_chart):
    charts =detection_accuracy.objects.values('names').annotate(dcount=Avg('ratio'))
    return render(request,"SProvider/likeschart.html", {'form':charts, 'like_chart':like_chart})


def Download_Predicted_DataSets(request):

    response = HttpResponse(content_type='application/ms-excel')
    # decide file name
    response['Content-Disposition'] = 'attachment; filename="Predicted_Datasets.xls"'
    # creating workbook
    wb = xlwt.Workbook(encoding='utf-8')
    # adding sheet
    ws = wb.add_sheet("sheet1")
    # Sheet header, first row
    row_num = 0
    font_style = xlwt.XFStyle()
    # headers are bold
    font_style.font.bold = True
    # writer = csv.writer(response)
    obj = cyber_attack_detection.objects.all()
    data = obj  # dummy method to fetch data.
    for my_row in data:
        row_num = row_num + 1

        ws.write(row_num, 0, my_row.Fid, font_style)
        ws.write(row_num, 1, my_row.Timestamp, font_style)
        ws.write(row_num, 2, my_row.Source_IP_Address, font_style)
        ws.write(row_num, 3, my_row.Destination_IP_Address, font_style)
        ws.write(row_num, 4, my_row.Source_Port, font_style)
        ws.write(row_num, 5, my_row.Destination_Port, font_style)
        ws.write(row_num, 6, my_row.Protocol, font_style)
        ws.write(row_num, 7, my_row.Packet_Length, font_style)
        ws.write(row_num, 8, my_row.Packet_Type, font_style)
        ws.write(row_num, 9, my_row.Traffic_Type, font_style)
        ws.write(row_num, 10, my_row.Payload_Data, font_style)
        ws.write(row_num, 11, my_row.Malware_Indicators, font_style)
        ws.write(row_num, 12, my_row.Anomaly_Scores, font_style)
        ws.write(row_num, 13, my_row.Alerts_Warnings, font_style)
        ws.write(row_num, 14, my_row.Attack_Signature, font_style)
        ws.write(row_num, 15, my_row.Action_Taken, font_style)
        ws.write(row_num, 16, my_row.Severity_Level, font_style)
        ws.write(row_num, 17, my_row.Device_Information, font_style)
        ws.write(row_num, 18, my_row.Network_Segment, font_style)
        ws.write(row_num, 19, my_row.Geo_City_location_Data, font_style)
        ws.write(row_num, 20, my_row.Proxy_Information, font_style)
        ws.write(row_num, 21, my_row.Firewall_Logs, font_style)
        ws.write(row_num, 22, my_row.IDS_IPS_Alerts, font_style)
        ws.write(row_num, 23, my_row.Log_Source, font_style)
        ws.write(row_num, 24, my_row.Prediction, font_style)


    wb.save(response)
    return response

def train_model(request):
    detection_accuracy.objects.all().delete()

    df = pd.read_csv('Datasets.csv')

    def apply_response(label):
        if (label == 'Malware'):
            return 0  # Malware
        elif (label == 'DDoS'):
            return 1  # DDoS
        elif (label == 'Intrusion'):
            return 2  # Intrusion

    df['results'] = df['Attack_Type'].apply(apply_response)

    cv = CountVectorizer()
    X = df['Payload_Data']
    y = df['results']

    print("Fid")
    print(X)
    print("Results")
    print(y)

    X = cv.fit_transform(X)

    models = []
    from sklearn.model_selection import train_test_split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.20)
    X_train.shape, X_test.shape, y_train.shape


    print(X_test)

    print("Artificial Neural Network (ANN)")

    from sklearn.neural_network import MLPClassifier
    mlpc = MLPClassifier().fit(X_train, y_train)
    y_pred = mlpc.predict(X_test)
    print("ACCURACY")
    print(accuracy_score(y_test, y_pred) * 100)
    print("CLASSIFICATION REPORT")
    print(classification_report(y_test, y_pred))
    print("CONFUSION MATRIX")
    print(confusion_matrix(y_test, y_pred))
    models.append(('MLPClassifier', mlpc))
    detection_accuracy.objects.create(names="Artificial Neural Network (ANN)",
                                      ratio=accuracy_score(y_test, y_pred) * 100)

    # SVM Model
    print("SVM")
    from sklearn import svm
    lin_clf = svm.LinearSVC()
    lin_clf.fit(X_train, y_train)
    predict_svm = lin_clf.predict(X_test)
    svm_acc = accuracy_score(y_test, predict_svm) * 100
    print(svm_acc)
    print("CLASSIFICATION REPORT")
    print(classification_report(y_test, predict_svm))
    print("CONFUSION MATRIX")
    print(confusion_matrix(y_test, predict_svm))
    models.append(('svm', lin_clf))
    detection_accuracy.objects.create(names="SVM", ratio=svm_acc)

    print("Logistic Regression")

    from sklearn.linear_model import LogisticRegression
    reg = LogisticRegression(random_state=0, solver='lbfgs').fit(X_train, y_train)
    y_pred = reg.predict(X_test)
    print("ACCURACY")
    print(accuracy_score(y_test, y_pred) * 100)
    print("CLASSIFICATION REPORT")
    print(classification_report(y_test, y_pred))
    print("CONFUSION MATRIX")
    print(confusion_matrix(y_test, y_pred))
    models.append(('logistic', reg))
    detection_accuracy.objects.create(names="Logistic Regression", ratio=accuracy_score(y_test, y_pred) * 100)

    print("Decision Tree Classifier")
    dtc = DecisionTreeClassifier()
    dtc.fit(X_train, y_train)
    dtcpredict = dtc.predict(X_test)
    print("ACCURACY")
    print(accuracy_score(y_test, dtcpredict) * 100)
    print("CLASSIFICATION REPORT")
    print(classification_report(y_test, dtcpredict))
    print("CONFUSION MATRIX")
    print(confusion_matrix(y_test, dtcpredict))
    models.append(('DecisionTreeClassifier', dtc))
    detection_accuracy.objects.create(names="Decision Tree Classifier", ratio=accuracy_score(y_test, dtcpredict) * 100)

    print("Gradient Boosting Classifier")

    from sklearn.ensemble import GradientBoostingClassifier
    clf = GradientBoostingClassifier(n_estimators=100, learning_rate=1.0, max_depth=1, random_state=0).fit(
        X_train,
        y_train)
    clfpredict = clf.predict(X_test)
    print("ACCURACY")
    print(accuracy_score(y_test, clfpredict) * 100)
    print("CLASSIFICATION REPORT")
    print(classification_report(y_test, clfpredict))
    print("CONFUSION MATRIX")
    print(confusion_matrix(y_test, clfpredict))
    models.append(('GradientBoostingClassifier', clf))
    detection_accuracy.objects.create(names="Gradient Boosting Classifier",
                                      ratio=accuracy_score(y_test, clfpredict) * 100)


    csv_format = 'Results.csv'
    df.to_csv(csv_format, index=False)
    df.to_markdown

    obj = detection_accuracy.objects.all()
    return render(request,'SProvider/train_model.html', {'objs': obj})
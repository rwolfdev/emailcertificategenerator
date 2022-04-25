using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.Security.Cryptography.X509Certificates;


namespace EmailCertificateGenerator
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        private void btn_generateCertificate_Click(object sender, RoutedEventArgs e)
        {
            X509Certificate2 cert = Certificates.GenerateCertificate(edt_email.Text, edt_company.Text, edt_password.Password);

            if (chb_importCertificate.IsChecked == true)
            {
                Certificates.SaveCertificate(cert);
            }

            System.IO.File.WriteAllBytes($".\\{edt_email.Text.Replace("@","_")}.mail.p12" ,cert.Export(X509ContentType.Pkcs12, edt_password.Password));
            System.IO.File.WriteAllBytes($".\\{edt_email.Text.Replace("@", "_")}.mail.cer", cert.Export(X509ContentType.Cert, edt_password.Password));
        }
    }
}

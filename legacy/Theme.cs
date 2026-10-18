using System.Drawing;
using System.Windows.Forms;

namespace SecretVault
{
    /// <summary>
    /// 界面配色与主题（取自 DH-BOX 界面原型的深浅两套 CSS 变量）。
    /// 用法：Theme.Apply("light"|"dark") 后调用 Theme.ApplyTo(窗体) 即可整体换肤。
    /// 控件用 Tag 标记用途："card"=卡片面板、"dim"/"faint"=次要文字、否则按默认。
    /// </summary>
    public static class Theme
    {
        public static string Current { get; private set; } = "light";
        public static bool IsDark => Current == "dark";

        // 浅色（原型默认）
        private static readonly Color[] Light =
        {
            ColorTranslator.FromHtml("#f2f4f9"), // Bg
            ColorTranslator.FromHtml("#ffffff"), // Card
            ColorTranslator.FromHtml("#eef1f8"), // Card2
            ColorTranslator.FromHtml("#dbe1ec"), // Line
            ColorTranslator.FromHtml("#1c2434"), // Text
            ColorTranslator.FromHtml("#5d6b84"), // TextDim
            ColorTranslator.FromHtml("#94a0b5"), // TextFaint
            ColorTranslator.FromHtml("#2f6fe4"), // Accent
            ColorTranslator.FromHtml("#2359bd"), // AccentStrong
            ColorTranslator.FromHtml("#e0485a"), // Danger
            ColorTranslator.FromHtml("#17a06b"), // Ok
            ColorTranslator.FromHtml("#f7f9fd"), // LogBg
            ColorTranslator.FromHtml("#eef2fa"), // Hover
            ColorTranslator.FromHtml("#c98a12"), // Warn
            ColorTranslator.FromHtml("#e8effc"), // AccentSoft
        };

        // 深色
        private static readonly Color[] Dark =
        {
            ColorTranslator.FromHtml("#0e1116"),
            ColorTranslator.FromHtml("#1a2130"),
            ColorTranslator.FromHtml("#202a3c"),
            ColorTranslator.FromHtml("#2b3648"),
            ColorTranslator.FromHtml("#e8edf5"),
            ColorTranslator.FromHtml("#8b96a8"),
            ColorTranslator.FromHtml("#5b6577"),
            ColorTranslator.FromHtml("#4f8cff"),
            ColorTranslator.FromHtml("#6ea2ff"),
            ColorTranslator.FromHtml("#ff5d6c"),
            ColorTranslator.FromHtml("#37c98b"),
            ColorTranslator.FromHtml("#141922"),
            ColorTranslator.FromHtml("#26314a"), // Hover
            ColorTranslator.FromHtml("#d8a63a"), // Warn
            ColorTranslator.FromHtml("#22304a"), // AccentSoft
        };

        public static Color Bg { get; private set; }
        public static Color Card { get; private set; }
        public static Color Card2 { get; private set; }
        public static Color Line { get; private set; }
        public static Color Text { get; private set; }
        public static Color TextDim { get; private set; }
        public static Color TextFaint { get; private set; }
        public static Color Accent { get; private set; }
        public static Color AccentStrong { get; private set; }
        public static Color Danger { get; private set; }
        public static Color Ok { get; private set; }
        public static Color LogBg { get; private set; }
        public static Color Hover { get; private set; }
        public static Color Warn { get; private set; }
        public static Color AccentSoft { get; private set; }

        static Theme() => Apply("light");

        /// <summary>切换（或指定）主题配色。</summary>
        public static void Apply(string theme)
        {
            Current = theme == "dark" ? "dark" : "light";
            var c = Current == "dark" ? Dark : Light;
            Bg = c[0]; Card = c[1]; Card2 = c[2]; Line = c[3];
            Text = c[4]; TextDim = c[5]; TextFaint = c[6];
            Accent = c[7]; AccentStrong = c[8]; Danger = c[9]; Ok = c[10];
            LogBg = c[11]; Hover = c[12]; Warn = c[13]; AccentSoft = c[14];
        }

        /// <summary>把当前配色递归应用到控件树。</summary>
        public static void ApplyTo(Control root)
        {
            switch (root)
            {
                case Form f:
                    f.BackColor = Bg;
                    f.ForeColor = Text;
                    break;
                case Button b:
                    b.FlatStyle = FlatStyle.Flat;
                    b.BackColor = b.Tag as string == "primary" ? Accent : Card2;
                    b.ForeColor = b.Tag as string == "primary" ? Color.White : Text;
                    b.FlatAppearance.BorderColor = b.Tag as string == "primary" ? Accent : Line;
                    b.FlatAppearance.MouseOverBackColor = b.Tag as string == "primary" ? AccentStrong : Hover;
                    break;
                case TextBox tb:
                    tb.BackColor = tb.ReadOnly ? LogBg : Card;
                    tb.ForeColor = Text;
                    tb.BorderStyle = BorderStyle.FixedSingle;
                    break;
                case ListView lv:
                    lv.BackColor = Card;
                    lv.ForeColor = Text;
                    break;
                case TreeView tv:
                    tv.BackColor = Card;
                    tv.ForeColor = Text;
                    tv.LineColor = Line;
                    break;
                case TabControl tc:
                    tc.BackColor = Bg;
                    break;
                case TabPage tp:
                    tp.UseVisualStyleBackColor = false;
                    tp.BackColor = Bg;
                    break;
                case Label lb:
                    lb.BackColor = Color.Transparent;
                    lb.ForeColor = lb.Tag as string switch
                    {
                        "dim" => TextDim,
                        "faint" => TextFaint,
                        "accent" => Accent,
                        "danger" => Danger,
                        "ok" => Ok,
                        _ => Text,
                    };
                    break;
                case CheckBox cb:
                    cb.BackColor = Color.Transparent;
                    cb.ForeColor = Text;
                    break;
                case RadioButton rb:
                    rb.BackColor = Color.Transparent;
                    rb.ForeColor = Text;
                    break;
                case NumericUpDown nu:
                    nu.BackColor = Card;
                    nu.ForeColor = Text;
                    break;
                case DateTimePicker dtp:
                    dtp.CalendarMonthBackground = Card;
                    dtp.ForeColor = Text;
                    break;
                case FlowLayoutPanel fl:
                    // 流式/表格布局面板一律透明：由父容器（顶栏卡片 / 内容区背景）决定底色，
                    // 避免出现“灰蓝色块”与卡片的色差（与前端 .topbar / .toolbar 同底色一致）
                    fl.BackColor = Color.Transparent;
                    break;
                case TableLayoutPanel tlp:
                    tlp.BackColor = Color.Transparent;
                    break;
                case Panel p:
                    p.BackColor = p.Tag as string == "card" ? Card : Bg;
                    break;
                case SplitContainer sc:
                    sc.BackColor = Line;
                    sc.Panel1.BackColor = Bg;
                    sc.Panel2.BackColor = Bg;
                    break;
            }
            foreach (Control child in root.Controls) ApplyTo(child);
        }
    }
}

"""Checks for readable nonlinear bars and localized measurement labels."""
import json
import unittest
import xml.etree.ElementTree as ET

import generate_charts as charts


class ChartTests(unittest.TestCase):
    def test_extreme_ratios_stay_visible(self):
        self.assertGreater(charts.log_width(0.95271, 393.2125, 565), 50)
        self.assertGreater(charts.log_width(336, 4202825, 560), 180)
        self.assertEqual(charts.log_width(0, 1000, 560), 0)
        self.assertEqual(charts.log_width(1000, 1000, 560), 560)
        widths = [charts.log_width(x, 1000, 560) for x in (1, 10, 100, 1000)]
        self.assertEqual(widths, sorted(set(widths)))

    def test_localization_preserves_measurements(self):
        labels = json.loads((charts.ROOT / 'scripts/chart_labels_zh.json').read_text(encoding='utf-8'))
        content = charts.chinese_svg(charts.overview_chart(), labels)
        values = {e.text for e in ET.fromstring(content).iter()}
        for label in ('关键性能指标', '84.6 倍', '17.3 倍', '99.992%', '4,202,825 字节/次', '336 字节/次'):
            self.assertIn(label, values)
        self.assertNotIn('Performance at a glance', values)
        self.assertIn('柱长采用对数缩放', content)

    def test_all_benchmark_charts_disclose_scale(self):
        for render in (charts.overview_chart, charts.codec_chart, charts.native_chart, charts.rpc_chart):
            with self.subTest(chart=render.__name__):
                self.assertIn('Logarithmic bar lengths', render())


if __name__ == '__main__':
    unittest.main()

import os
import json
import argparse
import xlsxwriter
from xlsxwriter.utility import xl_rowcol_to_cell

DEFAULT_FILE_NAME = "report"

class ExcelReporter():
    SUMMARY_WORKSHEET_NAME = "Summary"
    TIME_COLUMN = 0
    CURRENT_COLUMN = 1
    VOLTAGE_COLUMN = 2
    POWER_COLUMN = 3
    MIN_FROM_TOP_OFFSET = 1
    MAX_FROM_TOP_OFFSET = 2
    AVG_FROM_TOP_OFFSET = 3

    CHART_FROM_TOP_OFFSET = 5
    CHART_FROM_LEFT_OFFSET = 5

    DATA_FROM_TOP_OFFSET = 5

    CHART_DEFAULT_WIDTH = 720
    CHART_DEFAULT_HEIGHT = 576

    def __init__(self, results, file_name=None):
        if file_name is None:
            file_name = DEFAULT_FILE_NAME
        self.file_name = file_name + ".xlsx"
        self.workbook = xlsxwriter.Workbook(self.file_name)
        self.results = results
        self.common_timeline = None

    def report(self):
        summary_worksheet = self.workbook.add_worksheet(self.SUMMARY_WORKSHEET_NAME)
        for rail in sorted(self.results.keys()):
            self.write_rail_sheet(rail, self.results[rail])
        self.insert_summary_sheet(summary_worksheet)

    def insert_summary_sheet(self, worksheet):
        self.write_column(worksheet, self.TIME_COLUMN, "Time", self.common_timeline)
        self.insert_summary_collumn(worksheet, self.CURRENT_COLUMN, "Sum Current")
        self.insert_summary_collumn(worksheet, self.POWER_COLUMN, "Sum Power")
        self.insert_statistic_formulas(worksheet, self.DATA_FROM_TOP_OFFSET + 1,
                                       self.DATA_FROM_TOP_OFFSET + len(self.common_timeline))
        self.insert_chart(worksheet, "Summary Power", self.TIME_COLUMN, self.POWER_COLUMN,
                          self.DATA_FROM_TOP_OFFSET + 1, self.DATA_FROM_TOP_OFFSET + len(self.common_timeline))

    def insert_summary_collumn(self, worksheet, column, title):
        summary = []
        self.write_column(worksheet, column, title, [])
        for i in range(0, len(self.common_timeline)):
            summary_formula = "=SUM("
            for rail in self.results.keys():
                summary_formula += rail + "!$" + xl_rowcol_to_cell(self.DATA_FROM_TOP_OFFSET + 1 + i, column) + ","
            summary_formula += ")"
            summary.append(summary_formula)
        for i in range(len(self.common_timeline)):
            self.insert_formula(worksheet, summary[i], self.DATA_FROM_TOP_OFFSET + 1 + i, column)

    def close_file(self):
        try:
            self.workbook.close()
        except IOError:
            raise RuntimeError("Can`t save data to file: {}. Seems fle already opened".format(self.file_name))
        print("Results saved to file: {}".format(self.file_name))

    def write_rail_sheet(self, rail_name, rail_results):
        worksheet = self.workbook.add_worksheet(rail_name)
        times = [res["time"] for res in rail_results["current"]]
        times = [mtime - min(times) for mtime in times]
        self.write_column(worksheet, self.TIME_COLUMN, "Time", times)
        currents = [res["value"] for res in rail_results["current"]]
        self.write_column(worksheet, self.CURRENT_COLUMN, "Current", currents)
        voltages = [res["value"] for res in rail_results["voltage"]]
        self.write_column(worksheet, self.VOLTAGE_COLUMN, "Voltage", voltages)
        min_len = min(len(rail_results["current"]), len(rail_results["voltage"]))
        power = ['=${} * ${}'.format(xl_rowcol_to_cell(self.DATA_FROM_TOP_OFFSET + i, self.CURRENT_COLUMN),
                                     xl_rowcol_to_cell(self.DATA_FROM_TOP_OFFSET + i, self.VOLTAGE_COLUMN))
                 for i in range(1, min_len + 1)]
        self.write_column(worksheet, self.POWER_COLUMN, "Power", power, column_type=str)
        self.insert_statistic_formulas(worksheet, self.DATA_FROM_TOP_OFFSET + 1,
                                       self.DATA_FROM_TOP_OFFSET + max(len(rail_results["current"]),
                                                                       len(rail_results["voltage"])
                                                                       )
                                       )
        self.insert_chart(worksheet, "{} {}".format(rail_name, "Power"), self.TIME_COLUMN, self.POWER_COLUMN,
                          self.DATA_FROM_TOP_OFFSET + 1, self.DATA_FROM_TOP_OFFSET + min_len)
        if self.common_timeline is None:
            self.common_timeline = times
        if len(times) < len(self.common_timeline):
            self.common_timeline = times

    def write_column(self, worksheet, column_number, column_header, data, column_type=float):
        offset = self.DATA_FROM_TOP_OFFSET
        worksheet.write(offset, column_number, column_header)
        offset += 1
        for i in range(len(data)):
            if column_type == float:
                worksheet.write_number(offset + i, column_number, data[i])
            else:
                worksheet.write(offset + i, column_number, str(data[i]))

    def insert_formula(self, worksheet, formula, row, col):
        worksheet.write_formula(row, col, formula)

    def insert_min_formula(self, worksheet, column, start_row, end_row):
        min_formula = "=MIN(${}:${})".format(xl_rowcol_to_cell(start_row, column),
                                             xl_rowcol_to_cell(end_row, column))
        self.insert_formula(worksheet, min_formula, self.MIN_FROM_TOP_OFFSET, column)

    def insert_max_formula(self, worksheet, column, start_row, end_row):
        min_formula = "=MAX(${}:${})".format(xl_rowcol_to_cell(start_row, column),
                                             xl_rowcol_to_cell(end_row, column))
        self.insert_formula(worksheet, min_formula, self.MAX_FROM_TOP_OFFSET, column)

    def insert_avg_formula(self, worksheet, column, start_row, end_row):
        min_formula = "=AVERAGE(${}:${})".format(xl_rowcol_to_cell(start_row, column),
                                                 xl_rowcol_to_cell(end_row, column))
        self.insert_formula(worksheet, min_formula, self.AVG_FROM_TOP_OFFSET, column)

    def insert_statistic_formulas(self, worksheet, start_row, end_row):
        worksheet.write(self.MIN_FROM_TOP_OFFSET, 0, "Min:")
        worksheet.write(self.MAX_FROM_TOP_OFFSET, 0, "Max:")
        worksheet.write(self.AVG_FROM_TOP_OFFSET, 0, "Avg:")

        self.insert_min_formula(worksheet, self.CURRENT_COLUMN, start_row, end_row)
        self.insert_min_formula(worksheet, self.POWER_COLUMN, start_row, end_row)

        self.insert_max_formula(worksheet, self.CURRENT_COLUMN, start_row, end_row)
        self.insert_max_formula(worksheet, self.POWER_COLUMN, start_row, end_row)

        self.insert_avg_formula(worksheet, self.CURRENT_COLUMN, start_row, end_row)
        self.insert_avg_formula(worksheet, self.POWER_COLUMN, start_row, end_row)

    def insert_chart(self, worksheet, title, categories_column, data_column, data_start_raw, data_end_raw):
        chart = self.workbook.add_chart({"type": "line"})
        chart.add_series({
            'name': title,
            'categories': [worksheet.name, data_start_raw, categories_column, data_end_raw, categories_column],
            'values': [worksheet.name, data_start_raw, data_column, data_end_raw, data_column]
        })
        chart.set_size({'width': self.CHART_DEFAULT_WIDTH, 'height': self.CHART_DEFAULT_HEIGHT})
        worksheet.insert_chart(xl_rowcol_to_cell(self.CHART_FROM_TOP_OFFSET, self.CHART_FROM_LEFT_OFFSET), chart)


def read_json(file_path):
    with open(file_path, "r") as json_file:
        return json.load(json_file)


def main(args):
    if not os.path.isfile(args.file):
        raise Exception("Result file: {}. Can`t be found. Plese check file name and path provided".format(args.file))
    data = read_json(args.file)
    reporter = ExcelReporter(data, args.file.split(".")[0])
    try:
        reporter.report()
    finally:
        reporter.close_file()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", help='JSON File with results', required=True)
    args = parser.parse_args()
    main(args)


"""
Cafy Placeholder class for pytest integeration
"""

from allure_commons._allure import StepContext as AllureStepContext

class Cafy:
    class CafyBaseException(Exception):
        pass

    class CompositeError(CafyBaseException):
        def __init__(self, exceptions=None, title="Composite Error: "):
            self.exceptions = self.flatten_exceptions(exceptions)
            self.title=title
            self.raised = False

        def flatten_exceptions(self,exceptions):
            exception_list = list()
            for exception in exceptions:
                print(exception)
                if isinstance(exception,Cafy.CompositeError):
                    exception_list += self.flatten_exceptions(exception.exceptions)
                elif isinstance(exception,list):
                    exception_list += self.flatten_exceptions(exception)
                else:
                    exception_list.append(exception)
            return exception_list

        def __str__(self):
            result = "{title} \n".format(title=self.title)
            for e in self.exceptions:
                filename = ""
                lineno = ""
                if e.__traceback__:
                    filename = e.__traceback__.tb_frame.f_code.co_filename
                    lineno = e.__traceback__.tb_lineno
                result += "    {filename}:{lineno}:{etype}({message})\n".format(
                    filename=filename,
                    lineno=lineno,
                    etype=e.__class__.__name__,
                    message=str(e))
            return result

        def __xrepr__(self):
            return self.__str__()

    class Globals: 
        pass
    
    class RunInfo:
        current_testcase = None
        current_failures = dict()
        active_exceptions = list()


    class TestcaseStatus:
        def __init__(self,name,status,message):
            self.name = name
            self.status = status
            self.message = message
            try:
                self.html_message = message.chain[0][1].message
            except:
                self.html_message = str(message)
            self.text_message = self.html_message
            if self.html_message:
                self.html_message = self.html_message.replace("\n","<br/>")
            else:
                self.html_message = ""

        def get_status(self):
            return repr(status)

    def step(title, **kwargs):
        if callable(title):
            return Cafy.StepContext(title.__name__, {}, **kwargs)(title)
        else:
            return Cafy.StepContext(title, {}, **kwargs)


    class StepContext(AllureStepContext):
        def __init__(self, title, params, logger=None, blocking=True):
            super().__init__(title, params)
            self.blocking = blocking
            self.logger = logger

        def __enter__(self):
            super().__enter__()

        def __exit__(self, exc_type, exc_val, exc_tb):
            super().__exit__(exc_type, exc_val, exc_tb)
            if not self.blocking:
                if exc_type:
                    self.logger.error("Step failed here: {exc_type}:{exc_val}".format(
                        exc_val=exc_val,
                        exc_type=exc_type,
                        exc_tb=exc_tb))
                    Cafy.RunInfo.active_exceptions.append(exc_val)

            return not self.blocking

        
    class StepScope():
        def __init__(self, title):
            self.title = title

        def __enter__(self):
            Cafy.RunInfo.active_exceptions = list()
            Cafy.RunInfo.current_failures[Cafy.RunInfo.current_testcase] = list()

        def __exit__(self, exc_type, exc_val, exc_tb):
            if Cafy.RunInfo.active_exceptions:
                new_list = list()
                for exc in Cafy.RunInfo.active_exceptions:
                    new_list.append(exc)
                Cafy.RunInfo.active_exceptions = list()
                raise Cafy.CompositeError(new_list)

            Cafy.RunInfo.current_failures[Cafy.RunInfo.current_testcase] = list()

    def scope(title="Cafy Scope"):
        return Cafy.StepScope(title=title)